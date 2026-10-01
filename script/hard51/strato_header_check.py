#!/usr/bin/env python3
"""Offline check of a STRATO (Blockstanbul) V2 header and its commit seals.

Rebuilds blockHash = keccak(RLP(header with signatures = [])) from the public REST block API,
then recovers every commit seal over keccak(blockHash || 0x02) and the proposer seal, and checks
them against the header's currentValidators. Standard library only (pure-Python keccak/secp256k1).

Usage: python3 script/hard51/strato_header_check.py https://noderpc.strato.nexus/strato-api/eth/v1.2/block/last/1
V3 headers (round, currentStakes, stakeUpdates; testnet "helium") are not handled by this script.
"""
import json,sys,urllib.request,calendar,datetime
# --- keccak256 (pure python)
RC=[0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
M=(1<<64)-1
def rol(x,n): return ((x<<n)|(x>>(64-n)))&M if n else x
def kf(A):
  for rc in RC:
    C=[A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
    D=[C[(x-1)%5]^rol(C[(x+1)%5],1) for x in range(5)]
    A=[[A[x][y]^D[x] for y in range(5)] for x in range(5)]
    B=[[0]*5 for _ in range(5)]
    for x in range(5):
      for y in range(5): B[y][(2*x+3*y)%5]=rol(A[x][y],ROT[x][y])
    A=[[B[x][y]^((~B[(x+1)%5][y])&B[(x+2)%5][y]) for y in range(5)] for x in range(5)]
    A[0][0]^=rc
  return A
def keccak(b):
  r=136; b=bytearray(b)+b'\x01'
  while len(b)%r: b+=b'\x00'
  b[-1]|=0x80
  A=[[0]*5 for _ in range(5)]
  for i in range(0,len(b),r):
    blk=b[i:i+r]
    for j in range(r//8):
      x,y=j%5,j//5; A[x][y]^=int.from_bytes(blk[8*j:8*j+8],'little')
    A=kf(A)
  return b''.join(A[j%5][j//5].to_bytes(8,'little') for j in range(4))
assert keccak(b'').hex()=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
# --- secp256k1 recover
P=2**256-2**32-977; N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(p,q):
  if p is None: return q
  if q is None: return p
  if p[0]==q[0] and (p[1]+q[1])%P==0: return None
  l=((3*p[0]*p[0])*pow(2*p[1],-1,P) if p==q else (q[1]-p[1])*pow(q[0]-p[0],-1,P))%P
  x=(l*l-p[0]-q[0])%P; return (x,(l*(p[0]-x)-p[1])%P)
def mul(k,p):
  r=None
  while k:
    if k&1: r=add(r,p)
    p=add(p,p); k>>=1
  return r
def recover(h,r,s,v):
  x=r; y2=(x**3+7)%P; y=pow(y2,(P+1)//4,P)
  if y%2!=v%2: y=P-y
  R=(x,y); e=int.from_bytes(h,'big'); ri=pow(r,-1,N)
  Q=add(mul(s*ri%N,R),mul((-e*ri)%N,G))
  return keccak(Q[0].to_bytes(32,'big')+Q[1].to_bytes(32,'big'))[-20:].hex()
# --- RLP
def enc_len(l,off):
  if l<=55: return bytes([off+l])
  bl=l.to_bytes((l.bit_length()+7)//8,'big'); return bytes([off+55+len(bl)])+bl
def rlp(o):
  if isinstance(o,list):
    p=b''.join(rlp(x) for x in o); return enc_len(len(p),0xc0)+p
  if len(o)==1 and o[0]<128: return o
  return enc_len(len(o),0x80)+o
def I(n): return b'' if n==0 else n.to_bytes((n.bit_length()+7)//8,'big')
H=bytes.fromhex
url=sys.argv[1]
blk=json.load(urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'clpr-probe'})))[0]
bd=blk['blockData']; print('block',bd['number'])
ts=calendar.timegm(datetime.datetime.strptime(bd['timestamp'],'%Y-%m-%dT%H:%M:%SZ').timetuple())
def sig(sg,order):
  r,s=H(sg['r']),H(sg['s'])
  if order: r,s=s,r
  return r+s+bytes([sg['v']])
for order in (0,1):
  ps=bd['proposalSignature']
  fields=[I(2),H(bd['parentHash']),H(bd['stateRoot']),H(bd['transactionsRoot']),H(bd['receiptsRoot']),H(bd['logsBloom']),I(bd['number']),I(ts),H(bd['extraData']),
    [H(v) for v in bd['currentValidators']],[H(v) for v in bd['newValidators']],[H(v) for v in bd['removedValidators']],
    ([sig(ps,order)] if ps else b''),[]]
  hdr=rlp(fields); bh=keccak(hdr)
  print('order',order,'computed',bh.hex(),'api',blk['blockHash'], 'MATCH' if bh.hex()==blk['blockHash'] else '')
  if bh.hex()==blk['blockHash']:
    print('header RLP bytes',len(hdr))
    msg=keccak(bh+b'\x02')
    vals=set(bd['currentValidators'])
    signers=[]
    for sg in bd['signatures']:
      r,s=int(sg['r'],16),int(sg['s'],16)
      a=recover(msg,r,s,sg['v']); b=recover(msg,s,r,sg['v'])
      signers.append((a in vals, b in vals))
    print('commit seals (r,s as given / swapped) in validator set:',signers)
    # proposer seal: keccak(rlp(header with proposal sig removed & sigs removed))
    f2=list(fields); f2[12]=b''; pm=keccak(rlp(f2))
    print('proposer in set:',recover(pm,int(ps['r'],16),int(ps['s'],16),ps['v']) in vals, recover(pm,int(ps['s'],16),int(ps['r'],16),ps['v']) in vals)
    print('n validators',len(vals),'n seals',len(bd['signatures']))
