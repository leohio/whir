// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {GoldilocksExt3} from "../GoldilocksExt3.sol";

contract GasProfile is Test {
    using GoldilocksExt3 for GoldilocksExt3.Ext3;

    function test_ext3_mul_gas() public {
        GoldilocksExt3.Ext3 memory a = GoldilocksExt3.Ext3(123456789, 987654321, 111111111);
        GoldilocksExt3.Ext3 memory b = GoldilocksExt3.Ext3(222222222, 333333333, 444444444);
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < 1000; i++) {
            a = a.mul(b);
        }
        uint256 g1 = gasleft();
        emit log_named_uint("1000x Ext3.mul", g0 - g1);
        emit log_named_uint("per Ext3.mul", (g0 - g1) / 1000);
    }

    function test_ext3_add_gas() public {
        GoldilocksExt3.Ext3 memory a = GoldilocksExt3.Ext3(123456789, 987654321, 111111111);
        GoldilocksExt3.Ext3 memory b = GoldilocksExt3.Ext3(222222222, 333333333, 444444444);
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < 1000; i++) {
            a = a.add(b);
        }
        uint256 g1 = gasleft();
        emit log_named_uint("1000x Ext3.add", g0 - g1);
        emit log_named_uint("per Ext3.add", (g0 - g1) / 1000);
    }

    function test_ext3_mulScalar_gas() public {
        GoldilocksExt3.Ext3 memory a = GoldilocksExt3.Ext3(123456789, 987654321, 111111111);
        uint64 s = 42;
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < 1000; i++) {
            a = a.mulScalar(s);
        }
        uint256 g1 = gasleft();
        emit log_named_uint("1000x Ext3.mulScalar", g0 - g1);
        emit log_named_uint("per Ext3.mulScalar", (g0 - g1) / 1000);
    }

    function test_ext3_inv_gas() public {
        GoldilocksExt3.Ext3 memory a = GoldilocksExt3.Ext3(123456789, 987654321, 111111111);
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < 100; i++) {
            GoldilocksExt3.inv(a);
        }
        uint256 g1 = gasleft();
        emit log_named_uint("100x Ext3.inv", g0 - g1);
        emit log_named_uint("per Ext3.inv", (g0 - g1) / 100);
    }

    function test_keccak256_gas() public {
        bytes32 data = bytes32(uint256(12345));
        uint256 g0 = gasleft();
        for (uint256 i = 0; i < 1000; i++) {
            data = keccak256(abi.encodePacked(data, "squeeze", bytes8(uint64(i))));
        }
        uint256 g1 = gasleft();
        emit log_named_uint("1000x keccak256(47B)", g0 - g1);
        emit log_named_uint("per keccak256", (g0 - g1) / 1000);
    }
}
