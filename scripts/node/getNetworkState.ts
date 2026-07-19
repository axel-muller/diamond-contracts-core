import hre from "hardhat";
import type { Address } from "viem";

import type { } from "../../artifacts/contracts/ValidatorSetHbbft.sol/artifacts.js";
import type { } from "../../artifacts/contracts/ConnectivityTrackerHbbft.sol/artifacts.js";
import type { } from "../../artifacts/contracts/BlockRewardHbbft.sol/artifacts.js";

const ValidatorSetAddress: Address = "0x1000000000000000000000000000000000000001";
const ConnectivityTrackerAddress: Address = "0x1200000000000000000000000000000000000001";
const BlockRewardAddress: Address = "0x2000000000000000000000000000000000000001";

async function getNetworkState() {
  const { viem } = await hre.network.getOrCreate();

  const validatorSet = await viem.getContractAt("ValidatorSetHbbft", ValidatorSetAddress);
  const connectivityTracker = await viem.getContractAt("ConnectivityTrackerHbbft", ConnectivityTrackerAddress);
  const blockReward = await viem.getContractAt("BlockRewardHbbft", BlockRewardAddress);

  const epoch = await connectivityTracker.read.currentEpoch({ blockNumber: 450000n });
  console.log("[epoch] current epoch: ", await connectivityTracker.read.currentEpoch());
  console.log("[epoch] epoch faulty validators: ", await connectivityTracker.read.countFaultyValidators([epoch]));
  console.log(
    "[epoch] epoch - 1 faulty validators: ",
    await connectivityTracker.read.countFaultyValidators([epoch - 1n]),
  );
  console.log(
    "[epoch] epoch - 2 faulty validators: ",
    await connectivityTracker.read.countFaultyValidators([epoch - 2n]),
  );

  console.log("[validators] current: ", await validatorSet.read.getValidators());
  console.log("[validators] pending: ", await validatorSet.read.getPendingValidators());
  console.log("[validators] previous: ", await validatorSet.read.getPreviousValidators());

  const prevValidators = await validatorSet.read.getPreviousValidators();

  for (const validator of prevValidators) {
    console.log("\nvalidator: ", validator);
    console.log(
      "score epoch N: ",
      await connectivityTracker.read.getValidatorConnectivityScore([epoch, validator]),
    );
    console.log(
      "score epoch N-1: ",
      await connectivityTracker.read.getValidatorConnectivityScore([epoch - 1n, validator]),
    );
  }

  console.log("[block reward] fixed reward rate: ", await blockReward.read.VALIDATOR_FIXED_REWARD_PERCENT());
  console.log("[block reward] conn tracker: ", await blockReward.read.connectivityTracker());
  console.log("[conn tracker] bonus score system: ", await connectivityTracker.read.bonusScoreContract());

  console.log("[validator set] connectivityTracker: ", await validatorSet.read.connectivityTracker());
  console.log("[validator set] get staking: ", await validatorSet.read.getStakingContract());

  console.log("[conn tracker] flagged count: ", await connectivityTracker.read.getFlaggedValidatorsByEpoch([epoch]));
  console.log(
    "[conn tracker] flagged count epoch-1: ",
    await connectivityTracker.read.getFlaggedValidatorsByEpoch([epoch - 1n]),
  );

  console.log("[block reward] min validator reward: ", await blockReward.read.validatorMinRewardPercent([epoch]));

  for (let block = 449000n; block <= 450019n; block = block + 1n) {
    console.log(`block: ${block} -> early epoch end ${await blockReward.read.earlyEpochEnd({ blockNumber: block })}`);
    console.log(
      `block: ${block} -> current validators ${await validatorSet.read.getValidators({ blockNumber: block })}`,
    );
  }

  console.log("pending: ", await validatorSet.read.getPendingValidators({ blockNumber: 450009n }));

  for (const validator of prevValidators) {
    console.log(
      `${validator}            available since: ${await validatorSet.read.validatorAvailableSince([validator], {
        blockNumber: 450019n,
      })}`,
    );
    console.log(
      `${validator} available since last write: ${await validatorSet.read.validatorAvailableSinceLastWrite(
        [validator],
        { blockNumber: 450019n },
      )}`,
    );
  }
}

getNetworkState()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
