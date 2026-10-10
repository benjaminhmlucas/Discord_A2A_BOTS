const test = require('node:test');
const assert = require('node:assert/strict');
const child = require('node:child_process');
const { syncBuiltinESMExports } = require('node:module');
const { promisify } = require('node:util');

test('all child-process overloads preserve arguments, callbacks and options in both console modes', async () => {
  const methods = ['spawn','spawnSync','fork','exec','execSync','execFile','execFileSync'];
  const originals = Object.fromEntries(methods.map(name => [name,child[name]]));
  const prior = process.env.BOTBRIDGE_SHOW_CONSOLE;
  const calls = [];
  const callback = () => {};
  try {
    for (const method of methods)
      child[method] = function (...args) { calls.push({args,owner:this}); return 'fixture-result'; };
    require('../scripts/hidden_windows.cjs');
    const esm = await import('node:child_process');
    for (const show of ['0','1']) {
      process.env.BOTBRIDGE_SHOW_CONSOLE = show;
      const options = {stdio:'inherit',env:{SYNTHETIC:'fixture'},cwd:'fixture',windowsHide:false};
      const applied = {...options, windowsHide:show !== '1'};
      const bare = {windowsHide:show !== '1'};
      for (const method of methods) {
        assert.equal(esm[method],child[method]);
        function check(input, expected) {
          assert.equal(child[method](...input),'fixture-result');
          assert.deepEqual(calls.at(-1).args,expected);
          assert.equal(calls.at(-1).owner,child);
        }
        if (['spawn','spawnSync','fork'].includes(method)) {
          for (const args of [undefined,null,[],['--fixture']])
            check(['fixture',args,options],['fixture',args ?? [],applied]);
          check(['fixture',options],['fixture',applied]);
          check(['fixture'],['fixture',[],bare]);
        } else if (['exec','execSync'].includes(method)) {
          check(['fixture',options,callback],['fixture',applied,callback]);
          if (method === 'exec') check(['fixture',callback],['fixture',bare,callback]);
          else assert.throws(()=>child[method]('fixture',callback),TypeError);
          check(['fixture'],['fixture',bare,undefined]);
        } else {
          for (const args of [undefined,null,[],['--fixture']]) {
            check(['fixture',args,options,callback],['fixture',args ?? [],applied,callback]);
            if (method === 'execFile') check(['fixture',args,callback],['fixture',args ?? [],bare,callback]);
            else assert.throws(()=>child[method]('fixture',args,callback),TypeError);
          }
          if (method === 'execFile') check(['fixture',callback],['fixture',[],bare,callback]);
          else assert.throws(()=>child[method]('fixture',callback),TypeError);
          check(['fixture',options,callback],['fixture',[],applied,callback]);
          check(['fixture'],['fixture',[],bare,undefined]);
        }
        assert.equal(options.windowsHide,false);
        for (const invalid of [true,7,'invalid',[]])
          assert.throws(()=>['exec','execSync'].includes(method)
            ? child[method]('fixture',invalid) : child[method]('fixture',[],invalid),TypeError);
        if (['spawn','spawnSync','fork'].includes(method)) {
          check(['fixture',null,null],['fixture',[],bare]);
        } else if (['exec','execSync'].includes(method)) {
          check(['fixture',null],['fixture',bare,undefined]);
        } else check(['fixture',null,null],['fixture',[],bare,undefined]);
      }
      for (const method of ['exec','execFile']) {
        for (const failed of [false,true]) {
          const promise = promisify(child[method])('fixture',options);
          assert.equal(promise.child,'fixture-result');
          const args = calls.at(-1).args;
          assert.equal(args.at(-2).windowsHide,show !== '1');
          const error = failed ? new Error('fixture-error') : null;
          args.at(-1)(error,'fixture-output','fixture-stderr');
          if (failed) {
            await assert.rejects(promise, value => value === error &&
              value.stdout === 'fixture-output' && value.stderr === 'fixture-stderr');
          } else assert.deepEqual(await promise,{stdout:'fixture-output',stderr:'fixture-stderr'});
        }
      }
    }
  } finally {
    if (prior === undefined) delete process.env.BOTBRIDGE_SHOW_CONSOLE;
    else process.env.BOTBRIDGE_SHOW_CONSOLE = prior;
    Object.assign(child,originals);
    syncBuiltinESMExports();
  }
});
