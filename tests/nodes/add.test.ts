import type { NodeId } from 'polykey/dist/ids/types';
import type { Host } from 'polykey/dist/network/types';
import path from 'path';
import fs from 'fs';
import Logger, { LogLevel, StreamHandler } from '@matrixai/logger';
import { IdInternal } from '@matrixai/id';
import { sysexits } from 'polykey/dist/utils';
import PolykeyAgent from 'polykey/dist/PolykeyAgent';
import * as nodesUtils from 'polykey/dist/nodes/utils';
import NodeManager from 'polykey/dist/nodes/NodeManager';
import * as keysUtils from 'polykey/dist/keys/utils';
import * as testUtils from '../utils';

describe('add', () => {
  const logger = new Logger('add test', LogLevel.WARN, [new StreamHandler()]);
  const password = 'helloworld';
  const validNodeId = testUtils.generateRandomNodeId();
  const invalidNodeId = IdInternal.fromString<NodeId>('INVALIDID');
  const validHost = '0.0.0.0';
  const invalidHost = 'INVALIDHOST';
  const port = 55555;
  let dataDir: string;
  let nodePath: string;
  let pkAgent: PolykeyAgent;
  let mockedPingNode: jest.SpyInstance;
  beforeEach(async () => {
    dataDir = await fs.promises.mkdtemp(
      path.join(globalThis.tmpDir, 'polykey-test-'),
    );
    nodePath = path.join(dataDir, 'polykey');
    mockedPingNode = jest.spyOn(NodeManager.prototype, 'pingNode');
    // Cannot use the shared global agent since we can't 'un-add' a node
    pkAgent = await PolykeyAgent.createPolykeyAgent({
      password,
      nodePath,
      networkConfig: {
        agentHost: '127.0.0.1' as Host,
        clientHost: '127.0.0.1' as Host,
      },
      logger,
      keyRingConfig: {
        passwordOpsLimit: keysUtils.passwordOpsLimits.min,
        passwordMemLimit: keysUtils.passwordMemLimits.min,
        strictMemoryLock: false,
      },
    });
    await pkAgent.nodeGraph.stop();
    await pkAgent.nodeGraph.start({ fresh: true });
    mockedPingNode.mockImplementation(() => true);
  });
  afterEach(async () => {
    await pkAgent.stop();
    await fs.promises.rm(dataDir, {
      force: true,
      recursive: true,
    });
    mockedPingNode.mockRestore();
  });
  testUtils.testIf(testUtils.isTestPlatformEmpty)('adds a node', async () => {
    const { exitCode } = await testUtils.pkStdio(
      [
        'nodes',
        'add',
        nodesUtils.encodeNodeId(validNodeId),
        validHost,
        `${port}`,
      ],
      {
        env: {
          PK_NODE_PATH: nodePath,
          PK_PASSWORD: password,
        },
        cwd: dataDir,
      },
    );
    expect(exitCode).toBe(0);
    // Checking if node was added.
    const { stdout } = await testUtils.pkStdio(
      ['nodes', 'find', nodesUtils.encodeNodeId(validNodeId)],
      {
        env: {
          PK_NODE_PATH: nodePath,
          PK_PASSWORD: password,
        },
        cwd: dataDir,
      },
    );
    expect(stdout).toContain(validHost);
    expect(stdout).toContain(`${port}`);
  });
  testUtils.testIf(testUtils.isTestPlatformEmpty)(
    'fails to add a node (invalid node ID)',
    async () => {
      const { exitCode } = await testUtils.pkStdio(
        [
          'nodes',
          'add',
          nodesUtils.encodeNodeId(invalidNodeId),
          validHost,
          `${port}`,
        ],
        {
          env: {
            PK_NODE_PATH: nodePath,
            PK_PASSWORD: password,
          },
          cwd: dataDir,
        },
      );
      expect(exitCode).toBe(sysexits.USAGE);
    },
  );
  testUtils.testIf(testUtils.isTestPlatformEmpty)(
    'fails to add a node (invalid IP address)',
    async () => {
      const { exitCode } = await testUtils.pkStdio(
        [
          'nodes',
          'add',
          nodesUtils.encodeNodeId(validNodeId),
          invalidHost,
          `${port}`,
        ],
        {
          env: {
            PK_NODE_PATH: nodePath,
            PK_PASSWORD: password,
          },
          cwd: dataDir,
        },
      );
      expect(exitCode).toBe(sysexits.USAGE);
    },
  );
  testUtils.testIf(testUtils.isTestPlatformEmpty)(
    'adds a node with --force flag',
    async () => {
      const { exitCode } = await testUtils.pkStdio(
        [
          'nodes',
          'add',
          '--force',
          nodesUtils.encodeNodeId(validNodeId),
          validHost,
          `${port}`,
        ],
        {
          env: {
            PK_NODE_PATH: nodePath,
            PK_PASSWORD: password,
          },
          cwd: dataDir,
        },
      );
      expect(exitCode).toBe(0);
      // Checking if node was added.
      const node = await pkAgent.nodeGraph.getNode(validNodeId);
      expect(node?.address).toEqual({ host: validHost, port: port });
    },
  );
  testUtils.testIf(testUtils.isTestPlatformEmpty)(
    'fails to add node when ping fails',
    async () => {
      mockedPingNode.mockImplementation(() => false);
      const { exitCode } = await testUtils.pkStdio(
        [
          'nodes',
          'add',
          nodesUtils.encodeNodeId(validNodeId),
          validHost,
          `${port}`,
        ],
        {
          env: {
            PK_NODE_PATH: nodePath,
            PK_PASSWORD: password,
          },
          cwd: dataDir,
        },
      );
      expect(exitCode).toBe(sysexits.NOHOST);
    },
  );
  testUtils.testIf(testUtils.isTestPlatformEmpty)(
    'adds a node with --no-ping flag',
    async () => {
      mockedPingNode.mockImplementation(() => false);
      const { exitCode } = await testUtils.pkStdio(
        [
          'nodes',
          'add',
          '--no-ping',
          nodesUtils.encodeNodeId(validNodeId),
          validHost,
          `${port}`,
        ],
        {
          env: {
            PK_NODE_PATH: nodePath,
            PK_PASSWORD: password,
          },
          cwd: dataDir,
        },
      );
      expect(exitCode).toBe(0);
      // Checking if node was added.
      const node = await pkAgent.nodeGraph.getNode(validNodeId);
      expect(node?.address).toEqual({ host: validHost, port: port });
    },
  );
});