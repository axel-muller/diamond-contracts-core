import hre from "hardhat";
import { createPublicClient, http, type Address, type Hex } from "viem";

interface PendingTransaction {
  hash: Hex;
  from: Address;
  to: Address | null;
  input: Hex;
  value: Hex;
}

/// Transaction Replayer is able to replay pending transactions from one RPC on the configured network.
/// This might be a hardhat forked network, and synergises well with it to replay transactions that could not get included
/// in the original network, because it did lead to a problem in the block finalization.
/// Here is an example how to spin up a forked Network, used in testing of the alpha4 network.
/// Spin up a Node:
/// `pnpm hardhat node --fork http://62.171.133.46:54100 --fork-block-number 450019`
/// Add a new external network in the hardhat config.
///
/// ```json
// forked: {
///    type: "http",
///    chainType: "l1",
///    url: "http://127.0.0.1:8545",
///    timeout: 1_000_000
///},
/// ```
/// Then you can use the TransactionReplayer to replay the transactions from the original RPC.
/// ```typescript
/// import { TransactionReplayer } from "./forked/transactionReplayer.js";
/// const replayer = new TransactionReplayer("http://62.171.133.46:54100");
/// await replayer.replayAllPendingTransactions();
/// ```
export class TransactionReplayer {
  public constructor(public originalRPC: string) {}

  public async replayAllPendingTransactions() {
    const { viem, networkHelpers } = await hre.network.getOrCreate();

    const txs = await this.getPendingTransactions();

    for (const x of txs) {
      console.log("--- original hash:", x.hash);
      const tx = {
        to: x.to ?? undefined,
        data: x.input,
        value: BigInt(x.value),
        gas: 5_000_000n,
        gasPrice: 1_000_000_000n,
      };

      await networkHelpers.impersonateAccount(x.from);
      const signer = await viem.getWalletClient(x.from);

      try {
        const hash = await signer.sendTransaction(tx);
        console.log("OK: ", hash);
      } catch (e) {
        console.log("Error: ", { from: x.from, ...tx }, e);
      } finally {
        await networkHelpers.stopImpersonatingAccount(x.from);
      }
    }
  }

  public async getPendingTransactions(): Promise<PendingTransaction[]> {
    // retrieve the pending transactions from original RPC.
    // returns an array of pending transactions fetched from the RPC.

    const origClient = createPublicClient({ transport: http(this.originalRPC) });

    const pendingTransactions = await origClient.request({
      method: "parity_pendingTransactions" as never,
      params: [] as never,
    });

    return pendingTransactions as unknown as PendingTransaction[];
  }

  public async printBlockNumber() {
    const origClient = createPublicClient({ transport: http(this.originalRPC) });
    console.log("Block number: ", await origClient.getBlockNumber());
  }
}
