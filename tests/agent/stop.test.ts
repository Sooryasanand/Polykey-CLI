import path from 'path';
import fs from 'fs';
import Logger, { LogLevel, StreamHandler } from '@matrixai/logger';
import Status from 'polykey/dist/status/Status';
import config from 'polykey/dist/config';
import { sleep } from 'polykey/dist/utils';
import * as clientErrors from 'polykey/dist/client/errors';
import * as binErrors from '@/errors';
import * as testUtils from '../utils';

describe('stop', () => {
  const logger = new Logger('stop test', LogLevel.WARN, [new StreamHandler()]);
  let dataDir: string;
  beforeEach(async () => {
    dataDir = await fs.promises.mkdtemp(
      path.join(globalThis.tmpDir, 'polykey-test-'),
    );
  });
  afterEach(async () => {
    await fs.promises.rm(dataDir, {
      force: true,
      recursive: true,
    });
  });
  test(
    'stop LIVE agent',
    async () => {
      const password = 'abc123';
      const agentProcess = await testUtils.pkSpawn(
        [
          'agent',
          'start',
          '--client-host',
          '127.0.0.1',
          '--agent-host',
          '127.0.0.1',
          '--workers',
          'none',
          '--seed-nodes',
          '',
        ],
        {
          env: {
            PK_NODE_PATH: path.join(dataDir, 'polykey'),
            PK_PASSWORD: password,
            PK_PASSWORD_OPS_LIMIT: 'min',
            PK_PASSWORD_MEM_LIMIT: 'min',
          },
          cwd: dataDir,
        },
        logger,
      );
      const status = new Status({
        statusPath: path.join(dataDir, 'polykey', config.paths.statusBase),
        statusLockPath: path.join(
          dataDir,
          'polykey',
          config.paths.statusLockBase,
        ),
        fs,
        logger,
      });
      await status.waitFor('LIVE');
      await testUtils.pkExec(['agent', 'stop'], {
        env: {
          PK_NODE_PATH: path.join(dataDir, 'polykey'),
          PK_PASSWORD: password,
        },
        cwd: dataDir,
      });
      await status.waitFor('DEAD');
      await sleep(5000);
      agentProcess.kill();
    },
    globalThis.defaultTimeout * 2,
  );
  test(
    'stopping is idempotent during concurrent calls and STOPPING or DEAD status',
    async () => {
      const password = 'abc123';
      const passwordPath = path.join(dataDir, 'password');
      await fs.promises.writeFile(passwordPath, password);
      const status = new Status({
        statusPath: path.join(dataDir, 'polykey', config.paths.statusBase),
        statusLockPath: path.join(
          dataDir,
          'polykey',
          config.paths.statusLockBase,
        ),
        fs,
        logger,
      });
      const agentProcess = await testUtils.pkSpawn(
        [
          'agent',
          'start',
          '--client-host',
          '127.0.0.1',
          '--agent-host',
          '127.0.0.1',
          '--workers',
          'none',
          '--seed-nodes',
          '',
        ],
        {
          env: {
            PK_NODE_PATH: path.join(dataDir, 'polykey'),
            PK_PASSWORD: password,
            PK_PASSWORD_OPS_LIMIT: 'min',
            PK_PASSWORD_MEM_LIMIT: 'min',
          },
          cwd: dataDir,
        },
        logger,
      );
      await status.waitFor('LIVE');
      // Simultaneous calls to stop must use pkExec
      const [agentStop1, agentStop2] = await Promise.all([
        testUtils.pkExec(['agent', 'stop', '--password-file', passwordPath], {
          env: {
            PK_NODE_PATH: path.join(dataDir, 'polykey'),
          },
          cwd: dataDir,
        }),
        testUtils.pkExec(['agent', 'stop', '--password-file', passwordPath], {
          env: {
            PK_NODE_PATH: path.join(dataDir, 'polykey'),
          },
          cwd: dataDir,
        }),
      ]);
      // Cannot await for STOPPING
      // It's not reliable until file watching is implemented
      // So just 1 ms delay until sending another stop command
      await sleep(1);
      const agentStop3 = await testUtils.pkExec(
        ['agent', 'stop', '--node-path', path.join(dataDir, 'polykey')],
        {
          env: {
            PK_PASSWORD: password,
          },
          cwd: dataDir,
        },
      );
      await status.waitFor('DEAD');
      const agentStop4 = await testUtils.pkExec(
        ['agent', 'stop', '--password-file', passwordPath],
        {
          env: {
            PK_NODE_PATH: path.join(dataDir, 'polykey'),
          },
          cwd: dataDir,
        },
      );
      // If the GRPC server gets closed after the GRPC connection is established
      // then it's possible that one of these exit codes is 1
      if (agentStop1.exitCode === 1) {
        expect(agentStop2.exitCode).toBe(0);
      } else if (agentStop2.exitCode === 1) {
        expect(agentStop1.exitCode).toBe(0);
      } else {
        expect(agentStop1.exitCode).toBe(0);
        expect(agentStop2.exitCode).toBe(0);
      }
      expect(agentStop3.exitCode).toBe(0);
      expect(agentStop4.exitCode).toBe(0);
      agentProcess.kill();
    },
    globalThis.defaultTimeout * 2,
  );
  test.skip(
    'stopping starting agent results in error',
    async () => {
      // This relies on fast execution of `agent stop` while agent is starting,
      //  docker may not run this fast enough
      const password = 'abc123';
      const status = new Status({
        statusPath: path.join(dataDir, 'polykey', config.paths.statusBase),
        statusLockPath: path.join(
          dataDir,
          'polykey',
          config.paths.statusLockBase,
        ),
        fs,
        logger,
      });
      const agentProcess = await testUtils.pkSpawn(
        [
          'agent',
          'start',
          '--client-host',
          '127.0.0.1',
          '--agent-host',
          '127.0.0.1',
          '--workers',
          'none',
          '--verbose',
          '--seed-nodes',
          '',
        ],
        {
          env: {
            PK_NODE_PATH: path.join(dataDir, 'polykey'),
            PK_PASSWORD: password,
            PK_FAST_PASSWORD_HASH: 'true',
          },
          cwd: dataDir,
        },
        logger,
      );
      await status.waitFor('STARTING');
      const { exitCode, stderr } = await testUtils.pkStdio(
        ['agent', 'stop', '--format', 'json'],
        {
          env: {
            PK_NODE_PATH: path.join(dataDir, 'polykey'),
          },
          cwd: dataDir,
        },
      );
      testUtils.expectProcessError(exitCode, stderr, [
        new binErrors.ErrorPolykeyCLIAgentStatus('Agent is starting'),
      ]);
      await status.waitFor('LIVE');
      await testUtils.pkStdio(['agent', 'stop'], {
        env: {
          PK_NODE_PATH: path.join(dataDir, 'polykey'),
          PK_PASSWORD: password,
        },
        cwd: dataDir,
      });
      await status.waitFor('DEAD');
      agentProcess.kill();
    },
    globalThis.defaultTimeout * 2,
  );
  test(
    'stopping while unauthenticated does not stop',
    async () => {
      const password = 'abc123';
      const agentProcess = await testUtils.pkSpawn(
        [
          'agent',
          'start',
          '--client-host',
          '127.0.0.1',
          '--agent-host',
          '127.0.0.1',
          '--workers',
          'none',
          '--seed-nodes',
          '',
        ],
        {
          env: {
            PK_NODE_PATH: path.join(dataDir, 'polykey'),
            PK_PASSWORD: password,
            PK_PASSWORD_OPS_LIMIT: 'min',
            PK_PASSWORD_MEM_LIMIT: 'min',
          },
          cwd: dataDir,
        },
        logger,
      );
      const status = new Status({
        statusPath: path.join(dataDir, 'polykey', config.paths.statusBase),
        statusLockPath: path.join(
          dataDir,
          'polykey',
          config.paths.statusLockBase,
        ),
        fs,
        logger,
      });
      await status.waitFor('LIVE');
      const { exitCode, stderr } = await testUtils.pkExec(
        ['agent', 'stop', '--format', 'json'],
        {
          env: {
            PK_NODE_PATH: path.join(dataDir, 'polykey'),
            PK_PASSWORD: 'wrong password',
          },
          cwd: dataDir,
        },
      );
      testUtils.expectProcessError(exitCode, stderr, [
        new clientErrors.ErrorClientAuthDenied(),
      ]);
      // Should still be LIVE
      expect((await status.readStatus())?.status).toBe('LIVE');
      await testUtils.pkExec(['agent', 'stop'], {
        env: {
          PK_NODE_PATH: path.join(dataDir, 'polykey'),
          PK_PASSWORD: password,
        },
        cwd: dataDir,
      });
      await status.waitFor('DEAD');
      agentProcess.kill();
    },
    globalThis.defaultTimeout * 2,
  );
});
