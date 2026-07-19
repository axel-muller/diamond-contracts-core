import hre from "hardhat";
import {
  createPublicClient,
  decodeErrorResult,
  encodeFunctionData,
  http,
  type Address,
  type Hex,
} from "viem";

import type { } from "../../artifacts/contracts/BlockRewardHbbft.sol/artifacts.js";

const SystemAccountAddress: Address = "0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE";
const BlockRewardAddress: Address = "0x2000000000000000000000000000000000000001";

async function triggerReward() {
  const { viem, networkHelpers } = await hre.network.getOrCreate();

  const publicClient = await viem.getPublicClient();
  const blockReward = await viem.getContractAt("BlockRewardHbbft", BlockRewardAddress);

  console.log("[net] latest block: ", await publicClient.getBlockNumber());

  await networkHelpers.impersonateAccount(SystemAccountAddress);

  const txHash = await blockReward.write.reward([true], {
    account: SystemAccountAddress,
    gas: 5_000_000n,
    gasPrice: 0n,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });

  console.log("receipt: ", receipt);

  await networkHelpers.stopImpersonatingAccount(SystemAccountAddress);
}

async function getTxRevertReason() {
  const { viem } = await hre.network.getOrCreate();

  const blockReward = await viem.getContractAt("BlockRewardHbbft", BlockRewardAddress);

  const calldata = encodeFunctionData({
    abi: blockReward.abi,
    functionName: "reward",
    args: [true],
  });

  const remoteClient = createPublicClient({
    transport: http("http://62.171.133.46:54100"),
  });

  try {
    const result = await remoteClient.call({
      account: SystemAccountAddress,
      to: BlockRewardAddress,
      data: calldata,
      gas: 5_000_000n,
      gasPrice: 0n,
      blockNumber: 0x6dde3n,
    });

    console.log(result);
  } catch (e: unknown) {
    console.log(e);

    const data = extractRevertData(e);
    if (data === undefined) {
      throw e;
    }

    const revertReason = decodeErrorResult({
      abi: blockReward.abi,
      data,
    });
    console.log("Revert reason: ", revertReason);
  }
}

function extractRevertData(error: unknown): Hex | undefined {
  if (typeof error !== "object" || error === null) {
    return undefined;
  }

  const withData = error as { data?: unknown; cause?: unknown; walk?: () => unknown };
  if (typeof withData.data === "string" && withData.data.startsWith("0x")) {
    return withData.data as Hex;
  }

  if (typeof withData.walk === "function") {
    return extractRevertData(withData.walk());
  }

  return extractRevertData(withData.cause);
}

// Switch to getTxRevertReason() when debugging a remote revert.
triggerReward()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
