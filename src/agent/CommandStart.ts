import type { StdioOptions } from 'child_process';
import type {
  AgentStatusLiveData,
  AgentChildProcessInput,
  AgentChildProcessOutput,
} from '../types';
import type {
  default as PolykeyAgent,
  PolykeyAgentOptions,
} from 'polykey/dist/PolykeyAgent';
import type { DeepPartial } from 'polykey/dist/types';
import type { RecoveryCode } from 'polykey/dist/keys/types';
import childProcess from 'child_process';
import process from 'process';
import fs from 'fs';
import config from 'polykey/dist/config';
import * as keysErrors from 'polykey/dist/keys/errors';
import * as polykeyEvents from 'polykey/dist/events';
import * as polykeyUtils from 'polykey/dist/utils';
import CommandPolykey from '../CommandPolykey';
import * as binUtils from '../utils';
import * as binOptions from '../utils/options';
import * as binProcessors from '../utils/processors';
import * as errors from '../errors';

class CommandStart extends CommandPolykey {
  constructor(...args: ConstructorParameters<typeof CommandPolykey>) {
    super(...args);
    this.name('start');
    this.description('Start the Polykey Agent');
    this.addOption(binOptions.recoveryCodeFile);
    this.addOption(binOptions.recoveryCodeOutFile);
    this.addOption(binOptions.clientHost);
    this.addOption(binOptions.clientPort);
    this.addOption(binOptions.agentHost);
    this.addOption(binOptions.agentPort);
    this.addOption(binOptions.connConnectTime);
    this.addOption(binOptions.seedNodes);
    this.addOption(binOptions.network);
    this.addOption(binOptions.workers);
    this.addOption(binOptions.background);
    this.addOption(binOptions.backgroundOutFile);
    this.addOption(binOptions.backgroundErrFile);
    this.addOption(binOptions.fresh);
    this.addOption(binOptions.privateKeyFile);
    this.addOption(binOptions.passwordOpsLimit);
    this.addOption(binOptions.passwordMemLimit);
    this.addOption(binOptions.dnsServers);
    this.action(async (options) => {
      options.clientHost =
        options.clientHost ?? config.defaultsUser.clientServiceHost;
      options.clientPort =
        options.clientPort ?? config.defaultsUser.clientServicePort;
      const { default: PolykeyAgent } = await import(
        'polykey/dist/PolykeyAgent'
      );
      const nodesUtils = await import('polykey/dist/nodes/utils');
      const keysUtils = await import('polykey/dist/keys/utils');
      let password: string | undefined;
      if (options.fresh) {
        // If fresh, then get a new password
        password = await binProcessors.processNewPassword(
          options.passwordFile,
          this.fs,
        );
      } else if (options.recoveryCodeFile != null) {
        // If recovery code is supplied, then this is the new password
        password = await binProcessors.processNewPassword(
          options.passwordFile,
          this.fs,
        );
      } else if (await polykeyUtils.dirEmpty(this.fs, options.nodePath)) {
        // If the node path is empty, get a new password
        password = await binProcessors.processNewPassword(
          options.passwordFile,
          this.fs,
        );
      } else {
        // Otherwise this is the existing password
        // however, the code is capable of doing partial bootstrapping,
        // so it's possible that this is also a new password
        // if the root key isn't setup
        password = await binProcessors.processPassword(
          options.passwordFile,
          this.fs,
        );
      }
      const recoveryCodeIn = await binProcessors.processRecoveryCode(
        options.recoveryCodeFile,
        this.fs,
      );
      // Will be `[{}, true]` if `--seed-nodes` is not set
      // Will be '[{}, true]' if `--seed-nodes='<defaults>'`
      // Will be '[{...}, true]' if `--seed-nodes='...;<defaults>'`
      // Will be '[{}, false]' if `--seed-nodes=''`
      // Will be '[{...}, false]' if `--seed-nodes='...'`
      const [seedNodes, defaults] = options.seedNodes;
      let seedNodes_ = seedNodes;
      if (defaults) {
        try {
          seedNodes_ = {
            ...(await nodesUtils.resolveSeednodes(options.network)),
            ...seedNodes,
          };
        } catch (e) {
          this.logger.warn(e.message);
        }
      }
      // @ts-ignore: dynamic import of build-time metadata
      const buildJSON: any = await import('../build.json').then(
        (e) => e.default,
        () => ({}),
      );
      const agentOptions: DeepPartial<PolykeyAgentOptions> = {
        nodePath: options.nodePath,
        clientServiceHost: options.clientHost,
        clientServicePort: options.clientPort,
        agentServiceHost: options.agentHost,
        agentServicePort: options.agentPort,
        seedNodes: seedNodes_,
        workers: options.workers,
        keys: {
          recoveryCode: recoveryCodeIn,
          privateKeyPath: options.privateKeyFile,
          passwordOpsLimit:
            keysUtils.passwordOpsLimits[options.passwordOpsLimit],
          passwordMemLimit:
            keysUtils.passwordMemLimits[options.passwordMemLimit],
        },
        nodes: {
          // `--dns-server` with no value returns true, convert that to an empty list
          dnsServers: options.dnsServers === true ? [] : options.dnsServers,
        },
        versionMetadata: buildJSON.versionMetadata,
      };
      let statusLiveData: AgentStatusLiveData;
      let recoveryCodeOut: RecoveryCode | undefined;
      if (options.background) {
        const stdio: StdioOptions = ['ignore', 'ignore', 'ignore', 'ipc'];
        if (options.backgroundOutFile != null) {
          const agentOutFile = await this.fs.promises.open(
            options.backgroundOutFile,
            'w',
          );
          stdio[1] = agentOutFile.fd;
        }
        if (options.backgroundErrFile != null) {
          const agentErrFile = await this.fs.promises.open(
            options.backgroundErrFile,
            'w',
          );
          stdio[2] = agentErrFile.fd;
        }
        const agentProcess = childProcess.fork(
          globalThis.PK_MAIN_EXECUTABLE,
          ['--agent-mode'],
          {
            cwd: process.cwd(),
            env: process.env,
            detached: true,
            serialization: 'advanced',
            stdio,
          },
        );
        const {
          p: agentProcessP,
          resolveP: resolveAgentProcessP,
          rejectP: rejectAgentProcessP,
        } = polykeyUtils.promise<void>();
        // Once the agent responds with message, it considered ok to go-ahead
        agentProcess.once('message', (messageOut: AgentChildProcessOutput) => {
          if (messageOut.status === 'SUCCESS') {
            agentProcess.unref();
            agentProcess.disconnect();
            recoveryCodeOut = messageOut.recoveryCode;
            statusLiveData = { ...messageOut };
            delete statusLiveData['recoveryCode'];
            delete statusLiveData['status'];
            resolveAgentProcessP();
            return;
          } else {
            rejectAgentProcessP(
              new errors.ErrorPolykeyCLIAgentProcess(
                'Agent process responded with error',
                messageOut.error,
              ),
            );
            return;
          }
        });
        // Handle error event during abnormal spawning, this is rare
        agentProcess.once('error', (e) => {
          rejectAgentProcessP(
            new errors.ErrorPolykeyCLIAgentProcess(e.message),
          );
        });
        // If the process exits during initial execution of polykey-agent script
        // Then it is an exception, because the agent process is meant to be a long-running daemon
        agentProcess.once('close', (code, signal) => {
          rejectAgentProcessP(
            new errors.ErrorPolykeyCLIAgentProcess(
              'Agent process closed during fork',
              {
                data: {
                  code,
                  signal,
                },
              },
            ),
          );
        });
        const messageIn: AgentChildProcessInput = {
          logLevel: this.logger.getEffectiveLevel(),
          format: options.format,
          agentConfig: {
            password,
            options: agentOptions,
            fresh: options.fresh,
          },
        };
        agentProcess.send(messageIn, (e) => {
          if (e != null) {
            rejectAgentProcessP(
              new errors.ErrorPolykeyCLIAgentProcess(
                'Failed sending agent process message',
              ),
            );
          }
        });
        await agentProcessP;
      } else {
        // Change process name to polykey-agent
        process.title = 'polykey-agent';
        // eslint-disable-next-line prefer-const
        let pkAgent: PolykeyAgent;
        this.exitHandlers.handlers.push(async () => {
          await pkAgent?.stop();
        });
        try {
          pkAgent = await PolykeyAgent.createPolykeyAgent({
            fs: this.fs,
            logger: this.logger.getChild(PolykeyAgent.name),
            password,
            options: agentOptions,
            fresh: options.fresh,
          });
        } catch (e) {
          if (e instanceof keysErrors.ErrorKeyPairParse) {
            throw new errors.ErrorPolykeyCLIPasswordWrong();
          }
          throw e;
        }
        pkAgent.addEventListener(
          polykeyEvents.EventPolykeyAgentStop.name,
          () => {
            this.logger.warn('Stopping Agent');
          },
          { once: true },
        );
        recoveryCodeOut = pkAgent.keyRing.recoveryCode;
        statusLiveData = {
          pid: process.pid,
          nodeId: nodesUtils.encodeNodeId(pkAgent.keyRing.getNodeId()),
          clientHost: pkAgent.clientServiceHost,
          clientPort: pkAgent.clientServicePort,
          agentHost: pkAgent.agentServiceHost,
          agentPort: pkAgent.agentServicePort,
        };
      }
      process.stdout.write(
        binUtils.outputFormatter({
          type: options.format === 'json' ? 'json' : 'dict',
          data: {
            ...statusLiveData!,
            ...(recoveryCodeOut != null && options.recoveryCodeOutFile == null
              ? { recoveryCode: recoveryCodeOut }
              : {}),
          },
        }),
      );
      if (options.recoveryCodeOutFile != null && recoveryCodeOut != null) {
        await fs.promises.writeFile(
          options.recoveryCodeOutFile,
          recoveryCodeOut,
        );
      }
    });
  }
}

export default CommandStart;
