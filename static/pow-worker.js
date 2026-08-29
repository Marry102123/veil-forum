// SHA-256 PoW keeps verification cheap for the server and portable in browsers.
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
        const data = new TextEncoder().encode('veil-forum-pow-v2' + salt + challenge + nonce);
        const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
        if(hasLeadingZeros(hash, difficulty)){
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
