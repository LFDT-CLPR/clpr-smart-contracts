// Regenerate the Tempo verifier fixtures from the Presto (mainnet) RPC.
//
//   node test/verifiers/tempo/fixtures/generate.js [outDir]
//
// Writes presto-tip.json, presto-boundary.json, and constants.json, to this directory unless
// `outDir` is given. Points are converted to the EIP-2537 uncompressed form with @noble/curves.
// Each fixture carries the key that signed its block: the key of epoch E is the one announced in
// the extraData of block E·L − 1. The boundary fixture also carries the key it announces. Every
// header hash and certificate is checked before anything is written.
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { keccak256 } from 'viem';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, writeFileSync } from 'node:fs';
const OUT = (process.argv[2] ?? dirname(fileURLToPath(import.meta.url))) + '/';
const hex = s => Uint8Array.from(Buffer.from(s.replace(/^0x/,''),'hex'));
const toHex = b => Buffer.from(b).toString('hex');
const pad64 = (n) => n.toString(16).padStart(128,'0');
const g1Unc = (P) => { const a=P.toAffine(); return pad64(a.x)+pad64(a.y); };
const g2Unc = (P) => { const a=P.toAffine(); return pad64(a.x.c0)+pad64(a.x.c1)+pad64(a.y.c0)+pad64(a.y.c1); };
async function rpc(host,method,params){ const r=await fetch('https://'+host,{method:'POST',headers:{'content-type':'application/json','user-agent':'curl/8.7.1'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})}); const j=await r.json(); if(j.error) throw new Error(JSON.stringify(j.error)); return j.result; }
// minimal RLP for the header
const encB=(b)=>{ if(b.length===1&&b[0]<0x80) return b; return Buffer.concat([encL(b.length,0x80),b]); };
const encL=(n,off)=>{ if(n<56) return Buffer.from([off+n]); let l=[]; while(n>0){l.unshift(n&0xff); n=Math.floor(n/256);} return Buffer.from([off+55+l.length,...l]); };
const encList=(items)=>{ const body=Buffer.concat(items); return Buffer.concat([encL(body.length,0xc0),body]); };
const qty=(v)=>{ const n=typeof v==='number'?BigInt(v):BigInt(v); if(n===0n) return encB(Buffer.alloc(0)); let h=n.toString(16); if(h.length%2) h='0'+h; return encB(Buffer.from(h,'hex')); };
const data=(h)=>encB(Buffer.from(h.slice(2),'hex'));
function headerRlp(h){
  const inner=[data(h.parentHash),data(h.sha3Uncles),data(h.miner),data(h.stateRoot),data(h.transactionsRoot),data(h.receiptsRoot),data(h.logsBloom),qty(h.difficulty),qty(h.number),qty(h.gasLimit),qty(h.gasUsed),qty(h.timestamp),data(h.extraData),data(h.mixHash),data(h.nonce)];
  for(const k of ['baseFeePerGas','withdrawalsRoot','blobGasUsed','excessBlobGas','parentBeaconBlockRoot','requestsHash']){ if(h[k]==null) break; inner.push(['baseFeePerGas','blobGasUsed','excessBlobGas'].includes(k)?qty(h[k]):data(h[k])); }
  const outer=[qty(h.mainBlockGeneralGasLimit),qty(h.sharedGasLimit),qty(h.timestampMillisPart),encList(inner)];
  if(h.consensusContext){ const c=h.consensusContext; outer.push(encList([qty(c.epoch),qty(c.view),qty(c.parentView),data(c.proposer)])); }
  return encList(outer);
}
// OnchainDkgOutcome: varint(epoch) ‖ summary(32) ‖ mode(1) ‖ total(4) ‖ varint(n) ‖ key(96) ‖ ...
function outcomeKey(extraData){
  const b=hex(extraData); let o=0;
  const varint=()=>{ let v=0n,s=0n; for(;;){ const x=b[o++]; if(x===undefined) throw new Error('truncated DKG outcome'); v|=BigInt(x&0x7f)<<s; if(!(x&0x80)) return v; s+=7n; } };
  const epoch=varint(); o+=37; const n=varint();
  if(n===0n||b.length<o+96) throw new Error('DKG outcome has no key');
  return { epoch:Number(epoch), key:toHex(b.slice(o,o+96)) };
}
const NAMESPACE=Buffer.from('TEMPO_FINALIZE');
const DST='BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';
function requireCertificate(proposal,sigC,keyC){
  const msg=Buffer.concat([Buffer.from([NAMESPACE.length]),NAMESPACE,Buffer.from(proposal)]);
  const h=bls.G1.hashToCurve(msg,{DST});
  const lhs=bls.pairing(bls.G1.ProjectivePoint.fromHex(toHex(sigC)),bls.G2.ProjectivePoint.BASE);
  const rhs=bls.pairing(h,bls.G2.ProjectivePoint.fromHex(keyC));
  if(!bls.fields.Fp12.eql(lhs,rhs)) throw new Error('certificate does not verify under the epoch key');
}
const host='rpc.presto.tempo.xyz';
const L=21600;
async function keyOfEpoch(e){
  const blk=await rpc(host,'eth_getBlockByNumber',['0x'+(e*L-1).toString(16),false]);
  const out=outcomeKey(blk.extraData);
  if(out.epoch!==e) throw new Error(`block ${e*L-1} announces epoch ${out.epoch}, expected ${e}`);
  return out.key;
}
async function fixture(cert, keyC, nextKeyC){
  const n=parseInt(cert.block.header.number,16);
  const blk=await rpc(host,'eth_getBlockByNumber',['0x'+n.toString(16),false]);
  const rlp=headerRlp(blk);
  if(keccak256('0x'+rlp.toString('hex'))!==blk.hash) throw new Error(`header RLP of block ${n} does not hash to ${blk.hash}`);
  const c=hex(cert.certificate); const p=c.length-96;
  const proposal=c.slice(0,p), sigC=c.slice(p,p+48), seed=c.slice(p+48);
  if('0x'+toHex(proposal.slice(-32))!==blk.hash) throw new Error(`certificate of block ${n} names another block`);
  requireCertificate(proposal,sigC,keyC);
  const o={ network:'presto', chainId:4217, blockNumber:n, epoch:cert.epoch, view:cert.view, digest:cert.digest, blockHash:blk.hash,
    headerRlp:'0x'+rlp.toString('hex'), proposal:'0x'+toHex(proposal), sigCompressed:'0x'+toHex(sigC),
    sigUncompressed:'0x'+g1Unc(bls.G1.ProjectivePoint.fromHex(toHex(sigC))), seedCompressed:'0x'+toHex(seed),
    keyCompressed:'0x'+keyC, keyUncompressed:'0x'+g2Unc(bls.G2.ProjectivePoint.fromHex(keyC)), extraDataBytes:(blk.extraData.length-2)/2 };
  if(nextKeyC){
    if(outcomeKey(blk.extraData).key!==nextKeyC) throw new Error(`block ${n} does not announce the next key`);
    o.nextKeyCompressed='0x'+nextKeyC;
    o.nextKeyUncompressed='0x'+g2Unc(bls.G2.ProjectivePoint.fromHex(nextKeyC));
  }
  console.log('block',n,'epoch',cert.epoch,'rlp',rlp.length,'B; extraData',o.extraDataBytes,'B');
  return o;
}
const tipCert=await rpc(host,'consensus_getFinalization',['latest']);
const e=Math.floor(parseInt(tipCert.block.header.number,16)/L); // current epoch
const keyE=await keyOfEpoch(e);        // signs the tip
const keyPrev=await keyOfEpoch(e-1);   // signs block e·L − 1, the last block of the previous epoch
const tip=await fixture(tipCert,keyE);
const boundary=await fixture(await rpc(host,'consensus_getFinalization',[{height:e*L-1}]),keyPrev,keyE);
// constants for Solidity
const negG2=g2Unc(bls.G2.ProjectivePoint.BASE.negate());
const constants={ negG2Generator:'0x'+negG2, g2Generator:'0x'+g2Unc(bls.G2.ProjectivePoint.BASE), g1Generator:'0x'+g1Unc(bls.G1.ProjectivePoint.BASE) };
mkdirSync(OUT,{recursive:true});
writeFileSync(OUT+'presto-tip.json',JSON.stringify(tip,null,1)+'\n');
writeFileSync(OUT+'presto-boundary.json',JSON.stringify(boundary,null,1)+'\n');
writeFileSync(OUT+'constants.json',JSON.stringify(constants,null,1)+'\n');
console.log('keys equal across the boundary (reshare):',keyPrev===keyE);
