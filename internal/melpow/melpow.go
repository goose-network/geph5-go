// Package melpow is a Go port of the melpow 0.1.2 crate (Themelio's MelPoW),
// the non-interactive proof of sequential work used by geph5's broker
// registration puzzle. It mirrors melpow::Proof::generate / verify / to_bytes
// exactly, with the Blake3HashFunction from geph5-broker-protocol's puzzle.rs:
//
//	hash(b, k) = blake3::keyed_hash(blake3::hash(k), b)
//
// The proof is a Cohen-Pietrzak PoSW DAG labeling subjected to Fiat-Shamir:
// 200 random "gamma" leaf labels plus their off-path siblings are published,
// and the verifier recomputes each gamma's label from its parents. Difficulty
// N means O(2^N) sequential work.
//
// This port exists so the zero-config geph provider can self-register an
// account secret against the production broker (get_puzzle -> solve_puzzle ->
// register_user_secret), exactly like the Rust GUI client's start_registration.
package melpow

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"

	"github.com/goose-network/geph5-go/internal/blake3"
	zeebo "github.com/zeebo/blake3"
)

// proofCertainty mirrors melpow's PROOF_CERTAINTY: the number of random gamma
// challenges published in a proof.
const proofCertainty = 200

// hashFn mirrors melpow::HashFunction as implemented by puzzle.rs's
// Blake3HashFunction: blake3::keyed_hash(blake3::hash(k), b).
func hashFn(b, k []byte) [32]byte {
	return blake3.KeyedHash(blake3.Hash(k), b)
}

// btsKey mirrors melpow::hash::bts_key(bts, key) = tmelcrypt::hash_keyed(key, bts)
// = blake3::keyed_hash(blake3::hash(key), bts).
func btsKey(bts, key []byte) [32]byte {
	return blake3.KeyedHash(blake3.Hash(key), bts)
}

// node mirrors melpow::node::Node { bv u64, len usize }. bv holds the path bits
// (bit i is the branch taken at depth i); len is the depth.
type node struct {
	bv  uint64
	len int
}

func newZero() node { return node{bv: 0, len: 0} }

// take mirrors Node::take(n): truncate to the low n bits, depth n.
func (n node) take(k int) node {
	return node{bv: n.bv & ((uint64(1) << uint(k)) - 1), len: k}
}

// append mirrors Node::append(bit): add one branch bit at the current depth.
func (n node) append(bit int) node {
	return node{bv: n.bv | (uint64(bit) << uint(n.len)), len: n.len + 1}
}

// getBit mirrors Node::get_bit(n).
func (n node) getBit(k int) uint64 { return (n.bv >> uint(k)) & 1 }

// uniqid mirrors Node::uniqid: (len << 56) | bv.
func (n node) uniqid() uint64 { return (uint64(n.len) << 56) | n.bv }

// toBytes mirrors Node::to_bytes: uniqid as 8 big-endian bytes.
func (n node) toBytes() [8]byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], n.uniqid())
	return out
}

// nodeFromBytes mirrors Node::from_bytes.
func nodeFromBytes(b []byte) (node, bool) {
	if len(b) < 8 {
		return node{}, false
	}
	uniqid := binary.BigEndian.Uint64(b[:8])
	return node{bv: uniqid << 8 >> 8, len: int(uniqid >> 56)}, true
}

// foreachParent mirrors Node::foreach_parent(n, f): at full depth, the parents
// are take(index).append(0) for each set bit; otherwise the two children.
func (n node) foreachParent(depth int, f func(node)) {
	if n.len == depth {
		for index := 0; index < depth; index++ {
			if (n.bv>>uint(index))&1 != 0 {
				f(n.take(index).append(0))
			}
		}
	} else {
		f(n.append(0))
		f(n.append(1))
	}
}

// acc is the cold-path Accumulator (used by Verify and key derivation). It
// mirrors melpow::hash::Accumulator: add prefixes each chunk with its 8-byte
// big-endian length; hash applies hashFn(accum, key).
type acc struct {
	buf []byte
	key []byte
}

func newAcc(key []byte) *acc { return &acc{key: key} }

func (a *acc) add(b []byte) *acc {
	var bl [8]byte
	binary.BigEndian.PutUint64(bl[:], uint64(len(b)))
	a.buf = append(a.buf, bl[:]...)
	a.buf = append(a.buf, b...)
	return a
}

func (a *acc) hash() [32]byte { return hashFn(a.buf, a.key) }

// genGammas mirrors melpow::gen_gammas: 200 leaf nodes derived from the puzzle.
func genGammas(puzzle []byte, difficulty int) []node {
	gammas := make([]node, proofCertainty)
	for index := 0; index < proofCertainty; index++ {
		gSeed := btsKey(puzzle, []byte(fmt.Sprintf("gamma-%d", index)))
		gInt := binary.LittleEndian.Uint64(gSeed[0:8])
		shift := uint(64 - difficulty)
		gInt = (gInt >> shift) << shift
		gInt = bits.Reverse64(gInt)
		gammas[index] = node{bv: gInt, len: difficulty}
	}
	return gammas
}

// gammaToPath mirrors melpow::gamma_to_path: the off-path sibling at each level.
func gammaToPath(gamma node) []node {
	n := gamma.len
	path := make([]node, n)
	for index := 0; index < n; index++ {
		path[index] = gamma.take(index).append(1 - int(gamma.getBit(index)))
	}
	return path
}

// Proof mirrors melpow::Proof: a map of node -> 32-byte label. Only the gamma
// leaves, their off-path siblings, and the root are retained.
type Proof struct {
	m map[node][32]byte
}

// prover holds the reusable hot-path state for calc_labels. chi (and thus
// Hash(chi)) is constant across every label, so a single keyed hasher and a
// single accumulator scratch buffer are reused for all O(2^difficulty) nodes.
type prover struct {
	difficulty   int
	hasher       *zeebo.Hasher
	scratch      []byte
	ell          map[node][32]byte
	proofMap     map[node][32]byte
	currentCount float64
	totalCount   float64
	onProgress   func(float64)
}

func (p *prover) accumReset() { p.scratch = p.scratch[:0] }

func (p *prover) accumAdd(b []byte) {
	var bl [8]byte
	binary.BigEndian.PutUint64(bl[:], uint64(len(b)))
	p.scratch = append(p.scratch, bl[:]...)
	p.scratch = append(p.scratch, b...)
}

func (p *prover) accumHash() [32]byte {
	p.hasher.Reset()
	_, _ = p.hasher.Write(p.scratch)
	var out [32]byte
	p.hasher.Sum(out[:0])
	return out
}

func (p *prover) emit(nd node, lab [32]byte) {
	if nd.len == p.difficulty {
		p.currentCount++
		if p.onProgress != nil {
			p.onProgress(p.currentCount / p.totalCount)
		}
	}
	if _, ok := p.proofMap[nd]; ok || nd.len == 0 {
		p.proofMap[nd] = lab
	}
}

// calcLabels mirrors melpow::node::calc_labels_helper: a depth-first labeling
// of the PoSW DAG. ell memoizes the left-child labels of the current path's
// ancestors so leaf cross-edges (foreach_parent) can read them.
func (p *prover) calcLabels(nd node) [32]byte {
	n := p.difficulty
	if nd.len == n {
		p.accumReset()
		tb := nd.toBytes()
		p.accumAdd(tb[:])
		nd.foreachParent(n, func(parent node) {
			lab := p.ell[parent]
			p.accumAdd(lab[:])
		})
		lab := p.accumHash()
		p.emit(nd, lab)
		return lab
	}
	left := nd.append(0)
	right := nd.append(1)
	l0 := p.calcLabels(left)
	p.ell[left] = l0
	l1 := p.calcLabels(right)
	delete(p.ell, left)
	p.accumReset()
	tb := nd.toBytes()
	p.accumAdd(tb[:])
	p.accumAdd(l0[:])
	p.accumAdd(l1[:])
	lab := p.accumHash()
	p.emit(nd, lab)
	return lab
}

// Generate mirrors melpow::Proof::generate_with_progress. onProgress (may be
// nil) is called with a fraction in [0,1] as leaf labels are computed.
func Generate(puzzle []byte, difficulty int, onProgress func(float64)) *Proof {
	proofMap := make(map[node][32]byte)
	chi := btsKey(puzzle, []byte("chi"))
	gammas := genGammas(puzzle, difficulty)
	var empty [32]byte
	for _, gamma := range gammas {
		for _, pn := range gammaToPath(gamma) {
			proofMap[pn] = empty
		}
		proofMap[gamma] = empty
	}

	chiKey := blake3.Hash(chi[:])
	hasher, err := zeebo.NewKeyed(chiKey[:])
	if err != nil {
		// chiKey is always 32 bytes; this cannot happen.
		panic("melpow: invalid chi key: " + err.Error())
	}
	p := &prover{
		difficulty: difficulty,
		hasher:     hasher,
		ell:        make(map[node][32]byte),
		proofMap:   proofMap,
		totalCount: math.Pow(2.0, float64(difficulty)),
		onProgress: onProgress,
	}
	p.calcLabels(newZero())
	return &Proof{m: proofMap}
}

// ToBytes mirrors melpow::Proof::to_bytes: each entry is 8 node bytes + 32 label
// bytes. Map iteration order is unspecified (the verifier rebuilds a map), so
// the byte order is not deterministic across runs; every ordering verifies.
func (p *Proof) ToBytes() []byte {
	out := make([]byte, 0, 40*len(p.m))
	for nd, lab := range p.m {
		tb := nd.toBytes()
		out = append(out, tb[:]...)
		out = append(out, lab[:]...)
	}
	return out
}

// FromBytes mirrors melpow::Proof::from_bytes.
func FromBytes(b []byte) (*Proof, bool) {
	if len(b)%40 != 0 {
		return nil, false
	}
	m := make(map[node][32]byte)
	for len(b) > 0 {
		nd, ok := nodeFromBytes(b[0:8])
		if !ok {
			return nil, false
		}
		var lab [32]byte
		copy(lab[:], b[8:40])
		m[nd] = lab
		b = b[40:]
	}
	return &Proof{m: m}, true
}

// Verify mirrors melpow::Proof::verify: recompute each gamma's label from its
// parents and check the merkle-like commitment. Returns false on any mismatch.
func (p *Proof) Verify(puzzle []byte, difficulty int) bool {
	if difficulty > 100 {
		return false
	}
	chi := btsKey(puzzle, []byte("chi"))
	gammas := genGammas(puzzle, difficulty)
	root := newZero()
	phi, ok := p.m[root]
	if !ok {
		return false
	}
	temp := make(map[node][32]byte, len(p.m))
	for k, v := range p.m {
		temp[k] = v
	}
	output := true
	for _, gamma := range gammas {
		label, ok := p.m[gamma]
		if !ok {
			output = false
			continue
		}
		// Verify the label is correctly calculated from its parents.
		a := newAcc(chi[:])
		tb := gamma.toBytes()
		a.add(tb[:])
		parentsOK := true
		gamma.foreachParent(difficulty, func(parent node) {
			parlab, ok := p.m[parent]
			if !ok {
				parentsOK = false
				return
			}
			a.add(parlab[:])
		})
		if !parentsOK {
			return false
		}
		if a.hash() != label {
			output = false
		}
		// Check the merkle-like commitment (replicated from melpow 0.1.2).
		for index := difficulty - 1; index >= 0; index-- {
			gl := gamma.take(index)
			l0, ok0 := temp[gl.append(0)]
			l1, ok1 := temp[gl.append(1)]
			if !ok0 || !ok1 {
				return false
			}
			h := newAcc(chi[:])
			gtb := gl.toBytes()
			h.add(gtb[:])
			h.add(l0[:])
			h.add(l1[:])
			temp[gl] = h.hash()
		}
		if phi != p.m[root] {
			output = false
		}
	}
	return output
}

// SolvePuzzle mirrors geph5_broker_protocol::puzzle::solve_puzzle: the
// base64 (standard, no padding) encoding of the generated proof's bytes. This
// is the `solution` string passed to broker.register_user_secret.
func SolvePuzzle(puzzle string, difficulty int, onProgress func(float64)) string {
	proof := Generate([]byte(puzzle), difficulty, onProgress)
	return base64.RawStdEncoding.EncodeToString(proof.ToBytes())
}

// VerifySolution mirrors geph5_broker_protocol::puzzle::verify_puzzle_solution.
func VerifySolution(puzzle string, difficulty int, solution string) bool {
	raw, err := base64.RawStdEncoding.DecodeString(solution)
	if err != nil {
		return false
	}
	proof, ok := FromBytes(raw)
	if !ok {
		return false
	}
	return proof.Verify([]byte(puzzle), difficulty)
}
