pragma solidity >=0.4.24 <0.7.0;

/*** Some of the functionalities are adapted from cryptokitties.co and dice2.win ***/

/// @title A facet of Okdice that manages special access privileges.
/// @author okdice.io
contract AccessControl {
    /// There are three roles managed here:
    ///
    ///     - The CEO: The CEO can reassign other roles and change the addresses of our dependent smart
    ///         contracts. It is also the only role that can unpause the smart contract. It is initially
    ///         set to the address that created the smart contract in the okdice constructor.
    ///
    ///     - The CFO: The CFO can withdraw funds from okdice contracts.
    ///
    ///     - The COO: The COO can settle the bet.
    ///

    /// @dev Emited when contract is upgraded
    event ContractUpgrade(address newContract);

    // The addresses of the accounts that can execute actions within each roles.
    address public ceoAddress;
    address public cfoAddress;
    address public cooAddress;//The address corresponding to a private key used to sign placeBet commits.

    // @dev Keeps track whether the contract is paused. When that is true, most actions are blocked
    bool public paused = false;

    /// @dev Access modifier for CEO-only functionality
    modifier onlyCEO() {
        require(msg.sender == ceoAddress,"sender must be ceo");
        _;
    }

    /// @dev Access modifier for CFO-only functionality
    modifier onlyCFO() {
        require(msg.sender == cfoAddress,"sender must be cfo");
        _;
    }

    /// @dev Access modifier for COO-only functionality
    modifier onlyCOO() {
        require(msg.sender == cooAddress,"sender must be coo");
        _;
    }

    /// @dev Access modifier for ceo/cfo/coo functionality
    modifier onlyCLevel() {
        require(
            msg.sender == cooAddress ||
            msg.sender == ceoAddress ||
            msg.sender == cfoAddress,"sender must be ceo/cfo/coo"
        );
        _;
    }

    /// @dev Assigns a new address to act as the CEO. Only available to the current CEO.
    /// @param _newCEO The address of the new CEO
    function setCEO(address _newCEO) external onlyCEO {
        require(_newCEO != address(0),"ceo must be not null");

        ceoAddress = _newCEO;
    }

    /// @dev Assigns a new address to act as the CFO. Only available to the current CEO.
    /// @param _newCFO The address of the new CFO
    function setCFO(address _newCFO) external onlyCEO {
        require(_newCFO != address(0),"cfo must be not null");

        cfoAddress = _newCFO;
    }

    /// @dev Assigns a new address to act as the COO. Only available to the current CEO.
    /// @param _newCOO The address of the new COO
    function setCOO(address _newCOO) external onlyCEO {
        require(_newCOO != address(0),"coo must be not null");

        cooAddress = _newCOO;
    }

    /*** Pausable functionality adapted from OpenZeppelin ***/

    /// @dev Modifier to allow actions only when the contract IS NOT paused
    modifier whenNotPaused() {
        require(!paused,"only when the contract IS NOT paused");
        _;
    }

    /// @dev Modifier to allow actions only when the contract IS paused
    modifier whenPaused {
        require(paused,"only when the contract IS paused");
        _;
    }

    /// @dev Called by any "C-level" role to pause the contract. Used only when
    ///  a bug or exploit is detected and we need to limit damage.
    function pause() external onlyCLevel whenNotPaused {
        paused = true;
    }

    /// @dev Unpauses the smart contract. Can only be called by the CEO, since
    ///  one reason we may pause the contract is when CFO or COO accounts are
    ///  compromised.
    /// @notice This is public rather than external so it can be called by
    ///  derived contracts.
    function unpause() public onlyCEO whenPaused {
        // can't unpause if contract was upgraded
        paused = false;
    }
}

/// @title A facet of Okdice that manages bets.
/// @author okdice.io
///
///  Ethereum smart contract, deployed at 0xBF96042D61937B1686B81557c3A92806F1727ECF.
///
///  Uses hybrid commit-reveal + block hash random number generation that is immune
///   to tampering by players, house and miners. Apart from being fully transparent,
///   this also allows arbitrarily high bets.
contract OkDice is AccessControl{
    /// *** Constants section

    // Each bet is deducted 1% in favour of the house, but no less than some minimum.
    uint constant HOUSE_EDGE_PERCENT = 1;
    uint constant HOUSE_EDGE_MINIMUM_AMOUNT = 0.0003 ether;

    // Bets lower than this amount do not participate in jackpot rolls (and are
    // not deducted JACKPOT_FEE).
    uint constant MIN_JACKPOT_BET = 0.1 ether;

    // Chance to win jackpot (currently 0.1%) and fee deducted into jackpot fund.
    uint constant JACKPOT_MODULO = 1000;
    uint constant JACKPOT_FEE = 0.001 ether;

    // There is minimum and maximum bets.
    uint constant MIN_BET = 0.01 ether;
    uint constant MAX_AMOUNT = 300000 ether;

    // Modulo is a number of equiprobable outcomes in a game:
    //  - 2 for coin flip
    //  - 3 for three color balls
    //  - 6 for dice
    //  - 6*6 = 36 for double dice
    //  - 100 for etheroll
    //  - 36 for roulette
    //  - 4, 13, 26, 52 for pokers
    //  - 36 for wheel
    //  etc.
    // It's called so because 256-bit entropy is treated like a huge integer and
    // the remainder of its division by modulo is considered bet outcome.
    uint constant MAX_MODULO = 253;
    uint constant MODULO_40  = 40;
    uint constant MODULO_80  = 80;
    uint constant MODULO_120 = 120;
    uint constant MODULO_160 = 160;
    uint constant MODULO_200 = 200;
    uint constant MODULO_240 = 240;

    // For modulos below this threshold rolls are checked against a bit mask,
    // thus allowing betting on any combination of outcomes. For example, given
    // modulo 6 for dice, 101000 mask (base-2, big endian) means betting on
    // 4 and 6; for games with modulos higher than threshold (Etheroll), a simple
    // limit is used, allowing betting on any outcome in [0, N) range.
    //
    // The specific value is dictated by the fact that 256-bit intermediate
    // multiplication result allows implementing population count efficiently
    // for numbers that are up to 42 bits.
    uint constant MAX_MASK_MODULO = 253;

    // This is a check on bet mask overflow.
    uint constant MAX_BET_MASK      = 2 ** MAX_MASK_MODULO;
    uint constant MAX_BET_MASK_40   = 2 ** MODULO_40;
    uint constant MAX_BET_MASK_80   = 2 ** MODULO_80;
    uint constant MAX_BET_MASK_120  = 2 ** MODULO_120;
    uint constant MAX_BET_MASK_160  = 2 ** MODULO_160;
    uint constant MAX_BET_MASK_200  = 2 ** MODULO_200;
    uint constant MAX_BET_MASK_240  = 2 ** MODULO_240;

    uint constant MASK_40       = 0xFFFFFFFFFF;
    uint constant BET_MASK_40   = 40;

    // EVM BLOCKHASH opcode can query no further than 256 blocks into the
    // past. Given that settleBet uses block hash of placeBet as one of
    // complementary entropy sources, we cannot process bets older than this
    // threshold. On rare occasions dice2.win croupier may fail to invoke
    // settleBet in this timespan due to technical issues or extreme Ethereum
    // congestion; such bets can be refunded via invoking refundBet.
    uint constant BET_EXPIRATION_BLOCKS = 250;

    // Adjustable max bet profit. Used to cap bets against dynamic odds.
    uint public maxProfit;

    // Accumulated jackpot fund.
    uint128 public jackpotSize;

    // Funds that are locked in potentially winning bets. Prevents contract from
    // committing to bets it cannot pay out.
    uint128 public lockedInBets;

    // A structure representing a single bet.
    struct Bet {
        // Wager amount in wei.
        uint128 amount;
        // Modulo of a game.
        uint8 modulo;
        // Number of winning outcomes, used to compute winning payment (* modulo/rollUnder),
        // and used instead of mask for games with modulo > MAX_MASK_MODULO.
        uint8 rollUnder;
        // Block number of placeBet tx.
        uint40 placeBlockNumber;
        // Bit mask representing winning bet outcomes (see MAX_MASK_MODULO comment).
        uint mask;
        // Address of a gambler, used to pay out winning bets.
        address gambler;
    }

    // Mapping from commits to all currently active & processed bets.
    mapping (uint => Bet) bets;

    // Events that are issued to make statistic recovery easier.
    event FailedPayment(address indexed beneficiary, uint amount);
    event Payment(address indexed beneficiary, uint amount);
    event JackpotPayment(address indexed beneficiary, uint amount);

    // This event is emitted in placeBet to record commit in the logs.
    event Commit(uint commit);

    /// @dev Change max bet reward. Setting this to zero effectively disables betting.
    function setMaxProfit(uint _maxProfit) public onlyCFO {
        require (_maxProfit < MAX_AMOUNT, "maxProfit should be a sane number.");
        maxProfit = _maxProfit;
    }

    /// @dev This function is used to bump up the jackpot fund. Cannot be used to lower it.
    function increaseJackpot(uint increaseAmount) external onlyCFO {
        require (increaseAmount <= address(this).balance, "Increase amount larger than balance.");
        require (jackpotSize + lockedInBets + increaseAmount <= address(this).balance, "Not enough funds.");
        jackpotSize += uint128(increaseAmount);
    }

    /// @dev Contract may be destroyed only when there are no ongoing bets,
    /// either settled or refunded. All funds are transferred to contract owner.
    function kill() external onlyCEO {
        require (lockedInBets == 0, "All bets should be processed (settled or refunded) before self-destruct.");
    
        address(uint160(cfoAddress)).transfer(address(this).balance);

        paused = true;       
        jackpotSize = 0;
    }


    /// @dev User bets on the game
    /// *** Betting logic
    /// Bet states:
    ///  amount == 0 && gambler == 0 - 'clean' (can place a bet)
    ///  amount != 0 && gambler != 0 - 'active' (can be settled or refunded)
    ///  amount == 0 && gambler != 0 - 'processed' (can clean storage)
    ///
    ///  NOTE: Storage cleaning is not implemented in this contract version; it will be added
    ///        with the next upgrade to prevent polluting Ethereum state with expired bets.

    /// Bet placing transaction - issued by the player.
    ///  betMask         - bet outcomes bit mask for modulo <= MAX_MASK_MODULO,
    ///                    [0, betMask) for larger modulos.
    ///  modulo          - game modulo.
    ///  commitLastBlock - number of the maximum block where "commit" is still considered valid.
    ///  commit          - Keccak256 hash of some secret "reveal" random number, to be supplied
    ///                    by the dice2.win croupier bot in the settleBet transaction. Supplying
    ///                    "commit" ensures that "reveal" cannot be changed behind the scenes
    ///                    after placeBet have been mined.
    ///  r, s, v         - components of ECDSA signature of (commitLastBlock, commit).
    ///
    /// Commit, being essentially random 256-bit number, is used as a unique bet identifier in
    /// the 'bets' mapping.
    ///
    /// Commits are signed with a block limit to ensure that they are used at most once - otherwise
    /// it would be possible for a miner to place a bet with a known commit/reveal pair and tamper
    /// with the blockhash. Croupier guarantees that commitLastBlock will always be not greater than
    /// placeBet block number plus BET_EXPIRATION_BLOCKS.
    function placeBet(uint betMask, uint modulo, uint commitLastBlock, uint commit, bytes32 r, bytes32 s,uint8 v) external payable whenNotPaused{
        // Check that the bet is in 'clean' state.
        Bet storage bet = bets[commit];
        require (bet.gambler == address(0), "Bet should be in a 'clean' state.");

        // Validate input data ranges.
        uint amount = msg.value;
        require (modulo > 1 && modulo <= MAX_MODULO, "Modulo should be within range.");
        require (amount >= MIN_BET && amount <= MAX_AMOUNT, "Amount should be within range.");
        require (betMask > 0 && betMask < MAX_BET_MASK, "Mask should be within range.");

        // Check that commit is valid - it has not expired and its signature is valid.
        require (block.number <= commitLastBlock, "Commit has expired.");

        // keccak256(abi.encodePacked(a, b)) is a way to compute the hash of structured data
        // (although be aware that it is possible to craft a “hash collision” using different function parameter types).
        bytes32 signatureHash = keccak256(abi.encodePacked(commitLastBlock, commit));

        //Verify that the elliptic curve digital signature is correct
        require(v==27||v==28,"Parameter v must be equal to 27 or 28");
        require (cooAddress == ecrecover(signatureHash, v, r, s), "ECDSA signature is not valid.");

        uint rollUnder;
        rollUnder = getRollUnder(modulo,betMask);

        // Winning amount and jackpot increase.
        uint possibleWinAmount;
        uint jackpotFee;

        (possibleWinAmount, jackpotFee) = getDiceWinAmount(amount, modulo, rollUnder);

        // Enforce max profit limit.
        require (possibleWinAmount <= amount + maxProfit, "maxProfit limit violation.");

        // Lock funds.
        lockedInBets += uint128(possibleWinAmount);
        jackpotSize += uint128(jackpotFee);

        // Check whether contract has enough funds to process this bet.
        require (jackpotSize + lockedInBets <= address(this).balance, "Cannot afford to lose this bet.");

        // Record commit in logs.
        emit Commit(commit);

        // Store bet parameters on blockchain.
        bet.amount = uint128(amount);
        bet.modulo = uint8(modulo);
        bet.rollUnder = uint8(rollUnder);
        bet.placeBlockNumber = uint40(block.number);
        bet.mask = betMask;
        bet.gambler = msg.sender;
    }

    /// @dev Get the rolling of the game.
    function getRollUnder(uint modulo,uint betMask) private pure returns (uint rollUnder) {

        if (modulo <= MODULO_40) {
            // Small modulo games specify bet outcomes via bit mask.
            // rollUnder is a number of 1 bits in this mask (population count).
            // This magic looking formula is an efficient way to compute population
            // count on EVM for numbers below 2**40.
            require(betMask > 0 && betMask < MAX_BET_MASK_40, "Mask should be within range.");
            rollUnder = ((betMask * POPCNT_MULT) & POPCNT_MASK) % POPCNT_MODULO;
           
        } else if (modulo <= MODULO_80) {
            require(betMask > 0 && betMask < MAX_BET_MASK_80, "Mask should be within range.");
           rollUnder = getRollUnderHelper(betMask, 2);
        } else if (modulo == 100) {
            //etheroll
            require(betMask > 0 && betMask <= modulo, "High modulo range, betMask larger than modulo.");
            rollUnder = betMask;
        } else if (modulo <= MODULO_120) {
            require(betMask > 0 && betMask < MAX_BET_MASK_120, "Mask should be within range.");
            rollUnder = getRollUnderHelper(betMask, 3);
        } else if (modulo <= MODULO_160) {
           require(betMask > 0 && betMask < MAX_BET_MASK_160, "Mask should be within range.");
            rollUnder = getRollUnderHelper(betMask, 4);
        } else if (modulo <= MODULO_200) {
            require(betMask > 0 && betMask < MAX_BET_MASK_200, "Mask should be within range.");
            rollUnder = getRollUnderHelper(betMask, 5);
        }else if (modulo <= MODULO_240) {
            require(betMask > 0 && betMask < MAX_BET_MASK_240, "Mask should be within range.");
            rollUnder = getRollUnderHelper(betMask, 6);
        }  else if (modulo <= MAX_MODULO) {
            require(betMask > 0 && betMask < MAX_BET_MASK, "Mask should be within range.");
             rollUnder = getRollUnderHelper(betMask, 7);
        }

        return rollUnder;
    }

    /// @dev The helper function of the getRollUnder()
    function getRollUnderHelper(uint betMask, uint n) private pure returns (uint rollUnder) {
        uint betMaskTemp = betMask;
        rollUnder += (((betMaskTemp & MASK_40) * POPCNT_MULT) & POPCNT_MASK) % POPCNT_MODULO;
        for (uint i = 1; i < n; i++) {
            betMaskTemp = betMaskTemp >> BET_MASK_40;
            rollUnder += (((betMaskTemp & MASK_40) * POPCNT_MULT) & POPCNT_MASK) % POPCNT_MODULO;
        }
        return rollUnder;
    }

    /// @dev This is the method used to settle 99% of bets. To process a bet with a specific
    /// "commit", settleBet should supply a "reveal" number that would Keccak256-hash to
    /// "commit". "blockHash" is the block hash of placeBet block as seen by croupier; it
    /// is additionally asserted to prevent changing the bet outcomes on Ethereum reorgs.
    function settleBet(uint reveal, bytes32 blockHash) external onlyCOO whenNotPaused{
        uint commit = uint(keccak256(abi.encodePacked(reveal)));

        Bet storage bet = bets[commit];
        uint placeBlockNumber = bet.placeBlockNumber;

        // Check that bet has not expired yet (see comment to BET_EXPIRATION_BLOCKS).
        require (block.number > placeBlockNumber, "settleBet in the same block as placeBet, or before.");
        require (block.number <= placeBlockNumber + BET_EXPIRATION_BLOCKS, "Blockhash can't be queried by EVM.");
        require (blockhash(placeBlockNumber) == blockHash,"blockhash(placeBlockNumber) must equal to blockHash");

        // Settle bet using reveal and blockHash as entropy sources.
        settleBetCommon(bet, reveal, blockHash);
    }


    /// @dev Common settlement code for settleBet.
    function settleBetCommon(Bet storage bet, uint reveal, bytes32 entropyBlockHash) private whenNotPaused{
        // Fetch bet parameters into local variables (to save gas).
        uint amount = bet.amount;
        uint modulo = bet.modulo;
        uint rollUnder = bet.rollUnder;
        address gambler = bet.gambler;

        require(gambler!=address(0),"Gambler's address can not be 0");

        // Check that bet is in 'active' state.
        require (amount != 0, "Bet should be in an 'active' state");

        // Move bet into 'processed' state already.
        bet.amount = 0;

        // The RNG - combine "reveal" and blockhash of placeBet using Keccak256. Miners
        // are not aware of "reveal" and cannot deduce it from "commit" (as Keccak256
        // preimage is intractable), and house is unable to alter the "reveal" after
        // placeBet have been mined (as Keccak256 collision finding is also intractable).
        bytes32 entropy = keccak256(abi.encodePacked(reveal, entropyBlockHash));

        // Do a roll by taking a modulo of entropy. Compute winning amount.
        uint dice = uint(entropy) % modulo;

        uint diceWinAmount;
        uint _jackpotFee;
        (diceWinAmount, _jackpotFee) = getDiceWinAmount(amount, modulo, rollUnder);

        uint diceWin = 0;
        uint jackpotWin = 0;

        // Determine dice outcome.
        if ((modulo != 100) && (modulo <= MAX_MASK_MODULO)) {
            // For small modulo games, check the outcome against a bit mask.
            if ((2 ** dice) & bet.mask != 0) {
                diceWin = diceWinAmount;
            }

        } else {
            // For larger modulos, check inclusion into half-open interval.
            if (dice < rollUnder) {
                diceWin = diceWinAmount;
            }

        }

        // Unlock the bet amount, regardless of the outcome.
        lockedInBets -= uint128(diceWinAmount);

        // Roll for a jackpot (if eligible).
        if (amount >= MIN_JACKPOT_BET) {
            // The second modulo, statistically independent from the "main" dice roll.
            // Effectively you are playing two games at once!
            uint jackpotRng = (uint(entropy) / modulo) % JACKPOT_MODULO;

            // Bingo!
            if (jackpotRng == 0) {
                jackpotWin = jackpotSize;
                jackpotSize = 0;
            }
        }

        // Log jackpot win.
        if (jackpotWin > 0) {
            emit JackpotPayment(gambler, jackpotWin);
        }

        // Send the funds to gambler.
        sendFunds(gambler, diceWin + jackpotWin == 0 ? 1 wei : diceWin + jackpotWin, diceWin);
    }

    /// @dev Refund transaction - return the bet amount of a roll that was not processed in a
    /// due timeframe. Processing such blocks is not possible due to EVM limitations (see
    /// BET_EXPIRATION_BLOCKS comment above for details). In case you ever find yourself
    /// in a situation like this, just contact us, however nothing
    /// precludes you from invoking this method yourself.
    function refundBet(uint commit) external onlyCOO whenNotPaused{
        // Check that bet is in 'active' state.
        Bet storage bet = bets[commit];
        uint amount = bet.amount;

        require (amount != 0, "Bet should be in an 'active' state");

        // Check that bet has already expired.
        require (block.number > bet.placeBlockNumber + BET_EXPIRATION_BLOCKS, "Blockhash can't be queried by EVM.");

        // Move bet into 'processed' state, release funds.
        bet.amount = 0;

        uint diceWinAmount;
        uint jackpotFee;
        (diceWinAmount, jackpotFee) = getDiceWinAmount(amount, bet.modulo, bet.rollUnder);

        lockedInBets -= uint128(diceWinAmount);
        jackpotSize -= uint128(jackpotFee);

        // Send the refund.
        sendFunds(bet.gambler, amount, amount);
    }

    /// @dev Get the expected win amount after house edge is subtracted.
    function getDiceWinAmount(uint amount, uint modulo, uint rollUnder) private pure returns (uint winAmount, uint jackpotFee) {
        require (0 < rollUnder && rollUnder <= modulo, "Win probability out of range.");

        //Bets lower than 0.1 ether do not participate in jackpot rolls
        jackpotFee = amount >= MIN_JACKPOT_BET ? JACKPOT_FEE : 0;

        //Each bet is deducted 1% in favour of the house, but no less than 0.0003 ether.
        uint houseEdge = amount * HOUSE_EDGE_PERCENT / 100;

        if (houseEdge < HOUSE_EDGE_MINIMUM_AMOUNT) {
            houseEdge = HOUSE_EDGE_MINIMUM_AMOUNT;
        }

        require (houseEdge + jackpotFee <= amount, "Bet doesn't even cover house edge.");
        winAmount = (amount - houseEdge - jackpotFee) * modulo / rollUnder;
    }

    /// @dev Helper routine to process the payment.
    function sendFunds(address beneficiary, uint amount, uint successLogAmount) private {
        require(beneficiary!=address(0),"Beneficiary's address can not be 0");
        uint balanceBeforeTransfer = address(this).balance;

     //   address payable x = address(uint160(beneficiary));
     address payable x = address(uint160(beneficiary));
        x.transfer(amount);

        if(address(this).balance == balanceBeforeTransfer - amount){
            emit Payment(beneficiary, successLogAmount);
        } else {
            emit FailedPayment(beneficiary, amount);
        }
    }

    // This are some constants making O(1) population count in placeBet possible.
    uint constant POPCNT_MULT = 0x0000000000002000000000100000000008000000000400000000020000000001;
    uint constant POPCNT_MASK = 0x0001041041041041041041041041041041041041041041041041041041041041;
    uint constant POPCNT_MODULO = 0x3F;
}

/// @title The main class
/// @author okdice.io
contract OkDiceCore is OkDice{

    // Set in case the core contract is broken and an upgrade is required
    address public newContractAddress;

    /// @dev Constructor. Deliberately does not take any parameters.
    constructor () public {
       // Starts paused.
        paused = true;

        // the creator of the contract is the initial CEO
        ceoAddress = msg.sender;

        // the creator of the contract is also the initial CFO
        cfoAddress = msg.sender;

        // the creator of the contract is also the initial COO
        cooAddress = msg.sender;

        lockedInBets = 0;
        jackpotSize = 0;
        maxProfit = 100 ether;
    }

    // Fallback function deliberately left empty. It's primary use case
    // is to top up the bank roll.
    function () external  payable {
    }

    /// @dev Used to mark the smart contract as upgraded, in case there is a serious
    ///  breaking bug. This method does nothing but keep track of the new contract and
    ///  emit a message indicating that the new address is set. It's up to clients of this
    ///  contract to update to the new contract address in that case. (This contract will
    ///  be paused indefinitely if such an upgrade takes place.)
    /// @param _v2Address new address
    function setNewAddress(address _v2Address) external onlyCEO whenPaused {
        // See README.md for updgrade plan
        newContractAddress = _v2Address;
        emit ContractUpgrade(_v2Address);
    }

    /// @dev Override unpause so it requires all external contract addresses
    ///  to be set before contract can be unpaused. Also, we can't have
    ///  newContractAddress set either, because then the contract was upgraded.
    /// @notice This is public rather than external so we can call super.unpause
    ///  without using an expensive CALL.
    function unpause() public onlyCEO whenPaused {
        require(newContractAddress == address(0),"newContractAddress address must be 0");

        // Actually unpause the contract.
        super.unpause();
    }

    /// @dev Allows the CFO to capture the balance available to the contract.
    function withdrawBalance(uint withdrawAmount) external onlyCFO {

        uint256 balance = address(this).balance;
        require (withdrawAmount <= balance, "Increase amount larger than balance.");
        require (jackpotSize + lockedInBets + withdrawAmount <= address(this).balance, "Not enough funds.");
       
        address(uint160(cfoAddress)).transfer(withdrawAmount);
    }
}