<?php

namespace Portier\Client;

/**
 * Limited DER encoding functions.
 */
final class DER
{
    private const BIT_ID_CONSTRUCTED = 0x1 << 5;

    public const ID_INTEGER = 2;
    public const ID_BIT_STRING = 3;
    public const ID_OBJECT_ID = 6;
    public const ID_SEQUENCE = 16 | self::BIT_ID_CONSTRUCTED;

    public const NULL = "\x05\0";

    private function __construct()
    {
    }

    /**
     * Encodes a value in DER identifier-length-contents format.
     *
     * @param self::ID_* $id
     */
    public static function encodeValue(int $id, string $content): string
    {
        $prefix = chr($id);

        $len = strlen($content);
        if ($len < 128) {
            $prefix .= chr($len);
        } else {
            // Assumption: we never encode anything larger than 2^31
            $enc = ltrim(pack('N', $len), "\0");
            $prefix .= chr(0x80 | strlen($enc));
            $prefix .= $enc;
        }

        return $prefix.$content;
    }

    /**
     * Encode an integer to base128.
     */
    public static function encodeBase128(int $num): string
    {
        $result = chr($num & 0x7F);
        $num >>= 7;
        while ($num > 0) {
            $result .= chr(($num & 0x7F) | 0x80);
            $num >>= 7;
        }

        return strrev($result);
    }

    /**
     * Encode a sequence of values.
     */
    public static function encodeSequence(string ...$values): string
    {
        return self::encodeValue(self::ID_SEQUENCE, implode('', $values));
    }

    /**
     * Encode an object identifier.
     */
    public static function encodeOid(int ...$values): string
    {
        $bin = '';
        foreach ($values as $value) {
            $bin .= self::encodeBase128($value);
        }

        return self::encodeValue(self::ID_OBJECT_ID, $bin);
    }

    /**
     * Encode some data as a bit string.
     */
    public static function encodeBitString(string $data): string
    {
        return self::encodeValue(self::ID_BIT_STRING, "\0".$data);
    }
}
