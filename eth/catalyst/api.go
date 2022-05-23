// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package catalyst implements the temporary eth1/eth2 RPC integration.
package catalyst

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	antithesis "antithesis.com/go/rand-source"

	"github.com/MariusVanDerWijden/FuzzyVM/filler"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	txfuzz "github.com/mariusvanderwijden/tx-fuzz"
)

// Register adds catalyst APIs to the full node.
func Register(stack *node.Node, backend *eth.Ethereum) error {
	log.Warn("Catalyst mode enabled", "protocol", "eth")
	stack.RegisterAPIs([]rpc.API{
		{
			Namespace:     "engine",
			Version:       "1.0",
			Service:       NewConsensusAPI(backend),
			Public:        true,
			Authenticated: true,
		},
		{
			Namespace:     "engine",
			Version:       "1.0",
			Service:       NewConsensusAPI(backend),
			Public:        true,
			Authenticated: false,
		},
	})
	return nil
}

type ConsensusAPI struct {
	eth          *eth.Ethereum
	remoteBlocks *headerQueue  // Cache of remote payloads received
	localBlocks  *payloadQueue // Cache of local payloads generated
}

// NewConsensusAPI creates a new consensus api for the given backend.
// The underlying blockchain needs to have a valid terminal total difficulty set.
func NewConsensusAPI(eth *eth.Ethereum) *ConsensusAPI {
	if eth.BlockChain().Config().TerminalTotalDifficulty == nil {
		panic("Catalyst started without valid total difficulty")
	}
	return &ConsensusAPI{
		eth:          eth,
		remoteBlocks: newHeaderQueue(),
		localBlocks:  newPayloadQueue(),
	}
}

// ForkchoiceUpdatedV1 has several responsibilities:
// If the method is called with an empty head block:
// 		we return success, which can be used to check if the catalyst mode is enabled
// If the total difficulty was not reached:
// 		we return INVALID
// If the finalizedBlockHash is set:
// 		we check if we have the finalizedBlockHash in our db, if not we start a sync
// We try to set our blockchain to the headBlock
// If there are payloadAttributes:
// 		we try to assemble a block with the payloadAttributes and return its payloadID
func (api *ConsensusAPI) ForkchoiceUpdatedV1(update beacon.ForkchoiceStateV1, payloadAttributes *beacon.PayloadAttributesV1) (beacon.ForkChoiceResponse, error) {
	log.Trace("Engine API request received", "method", "ForkchoiceUpdated", "head", update.HeadBlockHash, "finalized", update.FinalizedBlockHash, "safe", update.SafeBlockHash)
	if update.HeadBlockHash == (common.Hash{}) {
		log.Warn("Forkchoice requested update to zero hash")
		return beacon.STATUS_INVALID, nil // TODO(karalabe): Why does someone send us this?
	}
	// Check whether we have the block yet in our database or not. If not, we'll
	// need to either trigger a sync, or to reject this forkchoice update for a
	// reason.
	block := api.eth.BlockChain().GetBlockByHash(update.HeadBlockHash)
	if block == nil {
		// If the head hash is unknown (was not given to us in a newPayload request),
		// we cannot resolve the header, so not much to do. This could be extended in
		// the future to resolve from the `eth` network, but it's an unexpected case
		// that should be fixed, not papered over.
		header := api.remoteBlocks.get(update.HeadBlockHash)
		if header == nil {
			log.Warn("Forkchoice requested unknown head", "hash", update.HeadBlockHash)
			return beacon.STATUS_SYNCING, nil
		}
		// Header advertised via a past newPayload request. Start syncing to it.
		// Before we do however, make sure any legacy sync in switched off so we
		// don't accidentally have 2 cycles running.
		if merger := api.eth.Merger(); !merger.TDDReached() {
			merger.ReachTTD()
			api.eth.Downloader().Cancel()
		}
		log.Info("Forkchoice requested sync to new head", "number", header.Number, "hash", header.Hash())
		if err := api.eth.Downloader().BeaconSync(api.eth.SyncMode(), header); err != nil {
			return beacon.STATUS_SYNCING, err
		}
		return beacon.STATUS_SYNCING, nil
	}
	// Block is known locally, just sanity check that the beacon client does not
	// attempt to push us back to before the merge.
	if block.Difficulty().BitLen() > 0 || block.NumberU64() == 0 {
		var (
			td  = api.eth.BlockChain().GetTd(update.HeadBlockHash, block.NumberU64())
			ptd = api.eth.BlockChain().GetTd(block.ParentHash(), block.NumberU64()-1)
			ttd = api.eth.BlockChain().Config().TerminalTotalDifficulty
		)
		if td == nil || (block.NumberU64() > 0 && ptd == nil) {
			log.Error("TDs unavailable for TTD check", "number", block.NumberU64(), "hash", update.HeadBlockHash, "td", td, "parent", block.ParentHash(), "ptd", ptd)
			return beacon.STATUS_INVALID, errors.New("TDs unavailable for TDD check")
		}
		if td.Cmp(ttd) < 0 || (block.NumberU64() > 0 && ptd.Cmp(ttd) > 0) {
			log.Error("Refusing beacon update to pre-merge", "number", block.NumberU64(), "hash", update.HeadBlockHash, "diff", block.Difficulty(), "age", common.PrettyAge(time.Unix(int64(block.Time()), 0)))
			return beacon.ForkChoiceResponse{PayloadStatus: beacon.PayloadStatusV1{Status: beacon.INVALIDTERMINALBLOCK}, PayloadID: nil}, nil
		}
	}

	if rawdb.ReadCanonicalHash(api.eth.ChainDb(), block.NumberU64()) != update.HeadBlockHash {
		// Block is not canonical, set head.
		if err := api.eth.BlockChain().SetChainHead(block); err != nil {
			return beacon.STATUS_INVALID, err
		}
	} else {
		// If the head block is already in our canonical chain, the beacon client is
		// probably resyncing. Ignore the update.
		log.Info("Ignoring beacon update to old head", "number", block.NumberU64(), "hash", update.HeadBlockHash, "age", common.PrettyAge(time.Unix(int64(block.Time()), 0)), "have", api.eth.BlockChain().CurrentBlock().NumberU64())
	}
	api.eth.SetSynced()

	// If the beacon client also advertised a finalized block, mark the local
	// chain final and completely in PoS mode.
	if update.FinalizedBlockHash != (common.Hash{}) {
		if merger := api.eth.Merger(); !merger.PoSFinalized() {
			merger.FinalizePoS()
		}
		// TODO (MariusVanDerWijden): If the finalized block is not in our canonical tree, somethings wrong
		finalBlock := api.eth.BlockChain().GetBlockByHash(update.FinalizedBlockHash)
		if finalBlock == nil {
			log.Warn("Final block not available in database", "hash", update.FinalizedBlockHash)
			return beacon.STATUS_INVALID, errors.New("final block not available")
		} else if rawdb.ReadCanonicalHash(api.eth.ChainDb(), finalBlock.NumberU64()) != update.FinalizedBlockHash {
			log.Warn("Final block not in canonical chain", "number", block.NumberU64(), "hash", update.HeadBlockHash)
			return beacon.STATUS_INVALID, errors.New("final block not canonical")
		}
	}
	// TODO (MariusVanDerWijden): Check if the safe block hash is in our canonical tree, if not somethings wrong
	if update.SafeBlockHash != (common.Hash{}) {
		safeBlock := api.eth.BlockChain().GetBlockByHash(update.SafeBlockHash)
		if safeBlock == nil {
			log.Warn("Safe block not available in database")
			return beacon.STATUS_INVALID, errors.New("safe head not available")
		}
		if rawdb.ReadCanonicalHash(api.eth.ChainDb(), safeBlock.NumberU64()) != update.SafeBlockHash {
			log.Warn("Safe block not in canonical chain")
			return beacon.STATUS_INVALID, errors.New("safe head not canonical")
		}
	}
	// If payload generation was requested, create a new block to be potentially
	// sealed by the beacon client. The payload will be requested later, and we
	// might replace it arbitrarily many times in between.
	if payloadAttributes != nil {
		log.Info("Creating new payload for sealing")
		start := time.Now()

		data, err := api.assembleBlock(update.HeadBlockHash, payloadAttributes)
		if err != nil {
			log.Error("Failed to create sealing payload", "err", err)
			return api.validForkChoiceResponse(nil), err // valid setHead, invalid payload
		}
		id := computePayloadId(update.HeadBlockHash, payloadAttributes)
		api.localBlocks.put(id, data)

		log.Info("Created payload for sealing", "id", id, "elapsed", time.Since(start))
		return api.validForkChoiceResponse(&id), nil
	}
	return api.validForkChoiceResponse(nil), nil
}

// validForkChoiceResponse returns the ForkChoiceResponse{VALID}
// with the latest valid hash and an optional payloadID.
func (api *ConsensusAPI) validForkChoiceResponse(id *beacon.PayloadID) beacon.ForkChoiceResponse {
	currentHash := api.eth.BlockChain().CurrentBlock().Hash()
	return beacon.ForkChoiceResponse{
		PayloadStatus: beacon.PayloadStatusV1{Status: beacon.VALID, LatestValidHash: &currentHash},
		PayloadID:     id,
	}
}

// ExchangeTransitionConfigurationV1 checks the given configuration against
// the configuration of the node.
func (api *ConsensusAPI) ExchangeTransitionConfigurationV1(config beacon.TransitionConfigurationV1) (*beacon.TransitionConfigurationV1, error) {
	if config.TerminalTotalDifficulty == nil {
		return nil, errors.New("invalid terminal total difficulty")
	}
	ttd := api.eth.BlockChain().Config().TerminalTotalDifficulty
	if ttd.Cmp(config.TerminalTotalDifficulty.ToInt()) != 0 {
		log.Warn("Invalid TTD configured", "geth", ttd, "beacon", config.TerminalTotalDifficulty)
		return nil, fmt.Errorf("invalid ttd: execution %v consensus %v", ttd, config.TerminalTotalDifficulty)
	}

	if config.TerminalBlockHash != (common.Hash{}) {
		if hash := api.eth.BlockChain().GetCanonicalHash(uint64(config.TerminalBlockNumber)); hash == config.TerminalBlockHash {
			return &beacon.TransitionConfigurationV1{
				TerminalTotalDifficulty: (*hexutil.Big)(ttd),
				TerminalBlockHash:       config.TerminalBlockHash,
				TerminalBlockNumber:     config.TerminalBlockNumber,
			}, nil
		}
		return nil, fmt.Errorf("invalid terminal block hash")
	}
	return &beacon.TransitionConfigurationV1{TerminalTotalDifficulty: (*hexutil.Big)(ttd)}, nil
}

// GetPayloadV1 returns a cached payload by id.
func (api *ConsensusAPI) GetPayloadV1(payloadID beacon.PayloadID) (*beacon.ExecutableDataV1, error) {
	log.Trace("Engine API request received", "method", "GetPayload", "id", payloadID)
	data := api.localBlocks.get(payloadID)
	if data == nil {
		return nil, &beacon.UnknownPayload
	}
	return data, nil
}

// NewPayloadV1 creates an Eth1 block, inserts it in the chain, and returns the status of the chain.
func (api *ConsensusAPI) NewPayloadV1(params beacon.ExecutableDataV1) (beacon.PayloadStatusV1, error) {
	log.Trace("Engine API request received", "method", "ExecutePayload", "number", params.Number, "hash", params.BlockHash)
	block, err := beacon.ExecutableDataToBlock(params)
	if err != nil {
		log.Debug("Invalid NewPayload params", "params", params, "error", err)
		return beacon.PayloadStatusV1{Status: beacon.INVALIDBLOCKHASH}, nil
	}
	// If we already have the block locally, ignore the entire execution and just
	// return a fake success.
	if block := api.eth.BlockChain().GetBlockByHash(params.BlockHash); block != nil {
		log.Warn("Ignoring already known beacon payload", "number", params.Number, "hash", params.BlockHash, "age", common.PrettyAge(time.Unix(int64(block.Time()), 0)))
		hash := block.Hash()
		return beacon.PayloadStatusV1{Status: beacon.VALID, LatestValidHash: &hash}, nil
	}
	// If the parent is missing, we - in theory - could trigger a sync, but that
	// would also entail a reorg. That is problematic if multiple sibling blocks
	// are being fed to us, and even more so, if some semi-distant uncle shortens
	// our live chain. As such, payload execution will not permit reorgs and thus
	// will not trigger a sync cycle. That is fine though, if we get a fork choice
	// update after legit payload executions.
	parent := api.eth.BlockChain().GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		// Stash the block away for a potential forced forckchoice update to it
		// at a later time.
		api.remoteBlocks.put(block.Hash(), block.Header())

		// Although we don't want to trigger a sync, if there is one already in
		// progress, try to extend if with the current payload request to relieve
		// some strain from the forkchoice update.
		if err := api.eth.Downloader().BeaconExtend(api.eth.SyncMode(), block.Header()); err == nil {
			log.Debug("Payload accepted for sync extension", "number", params.Number, "hash", params.BlockHash)
			return beacon.PayloadStatusV1{Status: beacon.SYNCING}, nil
		}
		// Either no beacon sync was started yet, or it rejected the delivered
		// payload as non-integratable on top of the existing sync. We'll just
		// have to rely on the beacon client to forcefully update the head with
		// a forkchoice update request.
		log.Warn("Ignoring payload with missing parent", "number", params.Number, "hash", params.BlockHash, "parent", params.ParentHash)
		return beacon.PayloadStatusV1{Status: beacon.ACCEPTED}, nil
	}
	// We have an existing parent, do some sanity checks to avoid the beacon client
	// triggering too early
	var (
		td  = api.eth.BlockChain().GetTd(parent.Hash(), parent.NumberU64())
		ttd = api.eth.BlockChain().Config().TerminalTotalDifficulty
	)
	if td.Cmp(ttd) < 0 {
		log.Warn("Ignoring pre-merge payload", "number", params.Number, "hash", params.BlockHash, "td", td, "ttd", ttd)
		return beacon.PayloadStatusV1{Status: beacon.INVALIDTERMINALBLOCK}, nil
	}
	if block.Time() <= parent.Time() {
		log.Warn("Invalid timestamp", "parent", block.Time(), "block", block.Time())
		return api.invalid(errors.New("invalid timestamp")), nil
	}
	if !api.eth.BlockChain().HasBlockAndState(block.ParentHash(), block.NumberU64()-1) {
		api.remoteBlocks.put(block.Hash(), block.Header())
		log.Warn("State not available, ignoring new payload")
		return beacon.PayloadStatusV1{Status: beacon.ACCEPTED}, nil
	}
	log.Trace("Inserting block without sethead", "hash", block.Hash(), "number", block.Number)
	if err := api.eth.BlockChain().InsertBlockWithoutSetHead(block); err != nil {
		log.Warn("NewPayloadV1: inserting block failed", "error", err)
		return api.invalid(err), nil
	}
	// We've accepted a valid payload from the beacon client. Mark the local
	// chain transitions to notify other subsystems (e.g. downloader) of the
	// behavioral change.
	if merger := api.eth.Merger(); !merger.TDDReached() {
		merger.ReachTTD()
		api.eth.Downloader().Cancel()
	}
	hash := block.Hash()
	return beacon.PayloadStatusV1{Status: beacon.VALID, LatestValidHash: &hash}, nil
}

// computePayloadId computes a pseudo-random payloadid, based on the parameters.
func computePayloadId(headBlockHash common.Hash, params *beacon.PayloadAttributesV1) beacon.PayloadID {
	// Hash
	hasher := sha256.New()
	hasher.Write(headBlockHash[:])
	binary.Write(hasher, binary.BigEndian, params.Timestamp)
	hasher.Write(params.Random[:])
	hasher.Write(params.SuggestedFeeRecipient[:])
	var out beacon.PayloadID
	copy(out[:], hasher.Sum(nil)[:8])
	return out
}

// invalid returns a response "INVALID" with the latest valid hash set to the current head.
func (api *ConsensusAPI) invalid(err error) beacon.PayloadStatusV1 {
	currentHash := api.eth.BlockChain().CurrentHeader().Hash()
	errorMsg := err.Error()
	return beacon.PayloadStatusV1{Status: beacon.INVALID, LatestValidHash: &currentHash, ValidationError: &errorMsg}
}

// assembleBlock creates a new block and returns the "execution
// data" required for beacon clients to process the new block.
func (api *ConsensusAPI) assembleBlock(parentHash common.Hash, params *beacon.PayloadAttributesV1) (*beacon.ExecutableDataV1, error) {
	log.Info("Producing block", "parentHash", parentHash)
	block, err := api.eth.Miner().GetSealingBlock(parentHash, params.Timestamp, params.SuggestedFeeRecipient, params.Random)
	if err != nil {
		return nil, err
	}
	return api.mutateExecutableData(beacon.BlockToExecutableData(block)), nil
}

func weirdHash(data *beacon.ExecutableDataV1, hashes ...common.Hash) common.Hash {
	rand := antithesis.NewSource()
	rnd := rand.Int()
	switch rnd % 10 {
	case 0:
		log.Info("Using common.Hash", "rnd", rnd)
		return common.Hash{}
	case 1:
		log.Info("Using data.BlockHash", "rnd", rnd)
		return data.BlockHash
	case 2:
		log.Info("Using data.ParentHash", "rnd", rnd)
		return data.ParentHash
	case 3:
		log.Info("Using data.StateRoot", "rnd", rnd)
		return data.StateRoot
	case 4:
		log.Info("Using data.ReceiptRoot", "rnd", rnd)
		return data.ReceiptsRoot
	case 5:
		log.Info("Using data.Random", "rnd", rnd)
		return data.Random
	case 6:
		hash := hashes[rand.Int31n(int32(len(hashes)))]
		log.Info("Using random hash", "rnd", rnd)
		return hash
	default:

		hash := hashes[rand.Int31n(int32(len(hashes)))]
		newBytes := hash.Bytes()
		index := rand.Int31n(int32(len(newBytes)))
		i := rand.Int31n(8)
		log.Info("Using hash mixing", "rnd", rnd, "index", index)
		newBytes[index] = newBytes[index] ^ 1<<i
		return common.BytesToHash(newBytes)
	}
}

func weirdNumber(data *beacon.ExecutableDataV1, number uint64) uint64 {
	rand := antithesis.NewSource()
	rnd := rand.Int()
	switch rnd % 7 {
	case 0:
		log.Info("Returning 0", "rnd", rnd)
		return 0
	case 1:
		log.Info("Returning 1", "rnd", rnd)
		return 1
	case 2:
		r := rand.Uint64()
		log.Info("Returning random value", "rnd", rnd, "r", r)
		return r
	case 3:
		log.Info("Returning UINT64_MAX", "rnd", rnd)
		return ^uint64(0)
	case 4:
		log.Info("Returning increment", "rnd", rnd, "number", number)
		return number + 1
	case 5:
		log.Info("Returning decrement", "rnd", rnd, "number", number)
		return number - 1
	default:
		r := uint64(rand.Int63n(100000))
		log.Info("Returning random increment", "rnd", rnd, "number", number, "r", r)
		return number + r
	}
}

func (api *ConsensusAPI) mutateExecutableData(data *beacon.ExecutableDataV1) *beacon.ExecutableDataV1 {
	hashes := []common.Hash{
		data.BlockHash,
		data.ParentHash,
		api.eth.BlockChain().GetCanonicalHash(0),
		api.eth.BlockChain().GetCanonicalHash(data.Number - 255),
		api.eth.BlockChain().GetCanonicalHash(data.Number - 256),
		api.eth.BlockChain().GetCanonicalHash(data.Number - 257),
		api.eth.BlockChain().GetCanonicalHash(data.Number - 1000),
		api.eth.BlockChain().GetCanonicalHash(data.Number - 90001),
	}
	rand := antithesis.NewSource()
	rnd := rand.Int()
	switch rnd % 15 {
	case 1:
		log.Info("Mutating data.BlockHash", "rnd", rnd)
		data.BlockHash = weirdHash(data, hashes...)
	case 2:
		log.Info("Mutating data.ParentHash", "rnd", rnd)
		data.ParentHash = weirdHash(data, hashes...)
	case 3:
		log.Info("Mutating data.FeeRecipient", "rnd", rnd)
		data.FeeRecipient = common.Address{}
	case 4:
		log.Info("Mutating data.StateRoot", "rnd", rnd)
		data.StateRoot = weirdHash(data, data.StateRoot)
	case 5:
		log.Info("Mutating data.ReceiptsRoot", "rnd", rnd)
		data.ReceiptsRoot = weirdHash(data, data.ReceiptsRoot)
	case 6:
		log.Info("Mutating data.LogsBloom", "rnd", rnd)
		data.LogsBloom = make([]byte, 0)
	case 7:
		log.Info("Mutating data.Random", "rnd", rnd)
		data.Random = weirdHash(data, data.Random)
	case 8:
		log.Info("Mutating data.Number", "rnd", rnd)
		data.Number = weirdNumber(data, data.Number)
	case 9:
		log.Info("Mutating data.GasLimit", "rnd", rnd)
		data.GasLimit = weirdNumber(data, data.GasLimit)
	case 10:
		log.Info("Mutating data.GasUsed", "rnd", rnd)
		data.GasUsed = weirdNumber(data, data.GasUsed)
	case 11:
		log.Info("Mutating data.Timestamp", "rnd", rnd)
		data.Timestamp = weirdNumber(data, data.Timestamp)
	case 12:
		log.Info("Mutating data.ExtraData", "rnd", rnd)
		hash := weirdHash(data, common.Hash{})
		data.ExtraData = hash[:]
	case 13:
		log.Info("Mutating data.BaseFeePerGas", "rnd", rnd)
		data.BaseFeePerGas = big.NewInt(int64(weirdNumber(data, data.BaseFeePerGas.Uint64())))
	case 14:
		log.Info("Mutating data.BlockHash", "rnd", rnd)
		data.BlockHash = weirdHash(data, data.BlockHash)
	}
	if rand.Int()%2 == 0 {
		log.Info("Using correct blockhash")
		// Set correct blockhash in 50% of cases
		txs, _ := decodeTransactions(data.Transactions)
		txs, txhash := api.mutateTransactions(txs)
		number := big.NewInt(0)
		number.SetUint64(data.Number)
		header := &types.Header{
			ParentHash:  data.ParentHash,
			UncleHash:   types.EmptyUncleHash,
			Coinbase:    data.FeeRecipient,
			Root:        data.StateRoot,
			TxHash:      txhash,
			ReceiptHash: data.ReceiptsRoot,
			Bloom:       types.BytesToBloom(data.LogsBloom),
			Difficulty:  common.Big0,
			Number:      number,
			GasLimit:    data.GasLimit,
			GasUsed:     data.GasUsed,
			Time:        data.Timestamp,
			BaseFee:     data.BaseFeePerGas,
			Extra:       data.ExtraData,
			MixDigest:   data.Random,
		}
		block := types.NewBlockWithHeader(header).WithBody(txs, nil /* uncles */)
		data.BlockHash = block.Hash()
	}
	return data
}
func decodeTransactions(enc [][]byte) ([]*types.Transaction, error) {
	var txs = make([]*types.Transaction, len(enc))
	for i, encTx := range enc {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(encTx); err != nil {
			return nil, fmt.Errorf("invalid transaction %d: %v", i, err)
		}
		txs[i] = &tx
	}
	return txs, nil
}

// Used in tests to add a the list of transactions from a block to the tx pool.
func (api *ConsensusAPI) insertTransactions(txs types.Transactions) error {
	for _, tx := range txs {
		api.eth.TxPool().AddLocal(tx)
	}
	return nil
}

func (api *ConsensusAPI) mutateTransactions(txs []*types.Transaction) ([]*types.Transaction, common.Hash) {
	txhash := types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil))
	rand := antithesis.NewSource()
	rnd := rand.Int()
	switch rnd % 20 {
	case 1:
		// duplicate a txs
		i := rand.Intn(len(txs))
		log.Info("Duplicating transaction", "rnd", rnd, "i", i)
		tx := txs[i]
		txs = append(txs, tx)
	case 2:
		// replace a tx
		index := rand.Intn(len(txs))
		log.Info("Replacing transaction", "rnd", rnd, "i", index)
		b := make([]byte, 200)
		rand.Read(b)
		tx, err := txfuzz.RandomTx(filler.NewFiller(b))
		if err != nil {
			fmt.Println(err)
		}
		if rand.Int()%2 == 0 {
			txs[index] = tx
		} else {
			key := "0xaf5ead4413ff4b78bc94191a2926ae9ccbec86ce099d65aaf469e9eb1a0fa87f"
			sk := crypto.ToECDSAUnsafe(common.FromHex(key))
			chainid := big.NewInt(0x146998)
			signedTx, err := types.SignTx(tx, types.NewLondonSigner(chainid), sk)
			if err != nil {
				panic(err)
			}
			txs[index] = signedTx
		}
	case 3:
		// Add a huuuge transaction
		log.Info("Adding a huuge transaction", "rnd", rnd)
		gasLimit := uint64(7_800_000)
		code := []byte{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf3}
		bigSlice := make([]byte, randomSize())
		code = append(code, bigSlice...)
		nonce, err := api.eth.APIBackend.GetPoolNonce(context.Background(), common.HexToAddress("0xb02A2EdA1b317FBd16760128836B0Ac59B560e9D"))
		if err != nil {
			panic(err)
		}
		gasPrice, err := api.eth.APIBackend.SuggestGasTipCap(context.Background())
		if err != nil {
			panic(err)
		}
		tx := types.NewContractCreation(nonce, big.NewInt(0), gasLimit, gasPrice, code)

		key := "0xcdfbe6f7602f67a97602e3e9fc24cde1cdffa88acd47745c0b84c5ff55891e1b"
		sk := crypto.ToECDSAUnsafe(common.FromHex(key))
		chainid := big.NewInt(0x146998)
		signedTx, err := types.SignTx(tx, types.NewLondonSigner(chainid), sk)
		if err != nil {
			panic(err)
		}
		txs = append(txs, signedTx)
	}

	if rand.Int()%20 > 17 {
		// Recompute correct txhash in most cases
		log.Info("Recomputing correct txhash", "rnd")
		txhash = types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil))
	}
	return txs, txhash
}

func randomSize() int {
	rand := antithesis.NewSource()
	rnd := rand.Int31n(100)
	if rnd < 5 {
		return int(rand.Int31n(11 * 1024 * 1024))
	} else if rnd < 10 {
		return 128*1024 + 1
	} else if rnd < 20 {
		return int(rand.Int31n(128 * 1024))
	}
	return int(rand.Int31n(127 * 1024))
}
