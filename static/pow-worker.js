importScripts('/static/argon2-bundled.min.js');
function hasLeadingZeros(hash, bits){
  const full = Math.floor(bits/8);
  const rem = bits%8;
  for(let i=0;i<full;i++) if(hash[i]!==0) return false;
  if(rem>0){
    if(hash[full] >> (8-rem) !==0) return false;
  }
  return true;
}
self.onmessage = async (e) => {
  const d = e.data;
  if(d && d.type === 'start'){
    const challenge = d.challenge;
    const salt = d.salt;
    const difficulty = d.difficulty;
    let nonce = d.startNonce || 0;
    const expected = Math.pow(2, difficulty);
    try{
      while(true){
        const pass = salt + challenge + nonce;
        let res;
        try{
          res = await argon2.hash({
            pass: pass,
            salt: 'secure-forum-argon2-salt',
            time: 1,
            mem: 16384,
            hashLen: 32,
            parallelism: 1,
            type: argon2.ArgonType.Argon2id
          });
        }catch(err){
          self.postMessage({type:'error', message: err.message || String(err)});
          return;
        }
        if(hasLeadingZeros(res.hash, difficulty)){
          self.postMessage({type:'done', nonce: String(nonce)});
          return;
        }
        nonce++;
        if(nonce % 2 === 0){
          // throttle progress every 2 for smooth but not spam
          self.postMessage({type:'progress', nonce, expected});
        }
        // cooperative yield periodically to allow termination via terminate()
        if(nonce % 50 === 0){
          await new Promise(r=> setTimeout(r, 0));
        }
      }
    }catch(err){
      self.postMessage({type:'error', message: err.message});
    }
  } else if(d && d.type === 'abort'){
    self.close();
  }
};
