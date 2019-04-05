const crypto = require("crypto"); 
const ed25519 = require("../");
const ed25519_1 = require("@stablelib/ed25519");
const bn = require('jsbn').BigInteger;
var seed = crypto.randomBytes(32);
console.log("seed",seed.toString("hex"));
var pair0 = ed25519_1.generateKeyPairFromSeed(seed);
var pair = ed25519.keyPairFromSeed(seed);
console.log("pairs equal",pair.publicKey.equals(Buffer(pair0.publicKey)));
console.log("public key",pair.publicKey.toString("hex"));
var pair2;
var s = "1";
var bn3;
var signature;
try{
do{
  bn3 = new bn(pair.privateKey.toString("hex"),16);
  s+="0"
  bn3 = bn3.add(new bn(s,10));
  pair2 = ed25519.keyPairFromPrivateKey(Buffer.from(bn3.toString(16),"hex"));
  signature = pair2.sign("test");
 
}while(pair.publicKey.equals(pair2.publicKey)&&pair.verify("test",signature)&&ed25519_1.verify(pair.publicKey,"test",signature));
}catch(e){
  console.log("error",e);
}
console.log("number",bn3.toString(10),"s",s.substr(0,s.length-1));
var f = "1";
try{
do{
  bn3 = new bn(pair.privateKey.toString("hex"),16);
  f+="0"
  bn3 = bn3.subtract(new bn(f,10));
  pair2 = ed25519.keyPairFromPrivateKey(Buffer.from(bn3.toString(16),"hex"));
  signature = pair2.sign("test");
 
}while(pair.publicKey.equals(pair2.publicKey)&&!pair.privateKey.equals(pair2.privateKey)&&pair.verify("test",signature)&&ed25519_1.verify(pair.publicKey,"test",signature));
}catch(e){
  console.log("error",e);
}
console.log("number",bn3.toString(10),"f",f.substr(0,f.length-1));

var bn1 = new bn(f.substr(0,f.length-1),10);
var bn2 = new bn(s.substr(0,s.length-1),10);
    bn3 = bn1.add(bn2);
console.log(bn3.toString(10));
return;


function is_prime(n){
     if(bn(n).lt(3))
        return (bn(n).gt(1));
     else if (bn(n).mod(2).equals(0) || bn(n).mod( 3).equals(0))
        return false
     var i = bn(5);
     while(bn(i).mult(bn(i)).lt(n)){
        if(bn(n).mod(i).equals(0) || bn(n).mod(bn(i).add(2)).equals(0))
            return false
        i = bn(i).add(6);
     }
     return true
}
/// Diffie Hallman key exchange simple example
var p = bn(23);// prime number - public
var g = bn(5); // primitive root modulo p - public
var alice_random_number = bn(30); // private
var bob_random_number = bn(70); // private

var ag = bn(g).power(alice_random_number);
var ap = bn(ag).mod(p);// allice calculate ab and sends to bob - public

var bg = bn(g).power(bob_random_number);
var bp = bn(bg).mod(p);// bob calculate bp and sends to alice - public

var abp = bn(bp).power(alice_random_number);
var asp = bn(abp).mod(p); // alice calculate as - private (shared secret)
var bap = bn(ap).power(bob_random_number);
var bsp = bn(bap).mod(p); // bob calculate bs - private (shared secret)

console.log(`const p,g: ${p},${g} public`);
console.log(`ag,bg: ${ag},${bg} private`);
console.log(`ap,bp: ${ap},${bp} public` );
console.log(`abp,bap: ${abp},${bap} private`);
console.log(`secret key: ${asp},${bsp} private`);

