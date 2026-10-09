const test = require('node:test');
const assert = require('node:assert/strict');
const child = require('node:child_process');
const { syncBuiltinESMExports } = require('node:module');

test('provider preload hides async and sync native children, preserves options and ESM exports', async () => {
  const originals = {spawn:child.spawn, spawnSync:child.spawnSync};
  const calls = [];
  try {
    for (const method of ['spawn','spawnSync'])
      child[method] = function (...args) { calls.push({method,args,owner:this}); return 'fixture-result'; };
    require('../scripts/hidden_windows.cjs');
    const esm = await import('node:child_process');
    for (const method of ['spawn','spawnSync']) {
      assert.equal(esm[method],child[method]);
      const options = {stdio:'inherit',env:{SYNTHETIC:'fixture'},windowsHide:false};
      for (const argv of [[],['--fixture']]) {
        assert.equal(child[method]('fixture',argv,options),'fixture-result');
        assert.deepEqual(calls.at(-1).args,['fixture',argv,{...options,windowsHide:true}]);
        assert.equal(calls.at(-1).owner,child);
      }
      assert.equal(child[method]('fixture',options),'fixture-result');
      assert.deepEqual(calls.at(-1).args,['fixture',{...options,windowsHide:true}]);
      assert.equal(child[method]('fixture'),'fixture-result');
      assert.deepEqual(calls.at(-1).args,['fixture',{windowsHide:true}]);
      assert.equal(options.windowsHide,false);
    }
  } finally {
    Object.assign(child,originals);
    syncBuiltinESMExports();
  }
});
