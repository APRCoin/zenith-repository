// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "script/standard.h"

#include <arpa/inet.h>

namespace {
inline std::string ValueString(const std::vector<unsigned char>& vch)
{
    if (vch.size() <= 4)
        return strprintf("%d", CScriptNum(vch, false).getint());
    else
        return HexStr(vch);
}
} // anon namespace

using namespace std;

const char* GetOpName(opcodetype opcode)
{
    switch (opcode)
    {
    // push value
    case OP_0                      : return "0";
    case OP_PUSHDATA1              : return "OP_PUSHDATA1";
    case OP_PUSHDATA2              : return "OP_PUSHDATA2";
    case OP_PUSHDATA4              : return "OP_PUSHDATA4";
    case OP_1NEGATE                : return "-1";
    case OP_RESERVED               : return "OP_RESERVED";
    case OP_1                      : return "1";
    case OP_2                      : return "2";
    case OP_3                      : return "3";
    case OP_4                      : return "4";
    case OP_5                      : return "5";
    case OP_6                      : return "6";
    case OP_7                      : return "7";
    case OP_8                      : return "8";
    case OP_9                      : return "9";
    case OP_10                     : return "10";
    case OP_11                     : return "11";
    case OP_12                     : return "12";
    case OP_13                     : return "13";
    case OP_14                     : return "14";
    case OP_15                     : return "15";
    case OP_16                     : return "16";

    // control
    case OP_NOP                    : return "OP_NOP";
    case OP_VER                    : return "OP_VER";
    case OP_IF                     : return "OP_IF";
    case OP_NOTIF                  : return "OP_NOTIF";
    case OP_VERIF                  : return "OP_VERIF";
    case OP_VERNOTIF               : return "OP_VERNOTIF";
    case OP_ELSE                   : return "OP_ELSE";
    case OP_ENDIF                  : return "OP_ENDIF";
    case OP_VERIFY                 : return "OP_VERIFY";
    case OP_RETURN                 : return "OP_RETURN";

    // stack ops
    case OP_TOALTSTACK             : return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           : return "OP_FROMALTSTACK";
    case OP_2DROP                  : return "OP_2DROP";
    case OP_2DUP                   : return "OP_2DUP";
    case OP_3DUP                   : return "OP_3DUP";
    case OP_2OVER                  : return "OP_2OVER";
    case OP_2ROT                   : return "OP_2ROT";
    case OP_2SWAP                  : return "OP_2SWAP";
    case OP_IFDUP                  : return "OP_IFDUP";
    case OP_DEPTH                  : return "OP_DEPTH";
    case OP_DROP                   : return "OP_DROP";
    case OP_DUP                    : return "OP_DUP";
    case OP_NIP                    : return "OP_NIP";
    case OP_OVER                   : return "OP_OVER";
    case OP_PICK                   : return "OP_PICK";
    case OP_ROLL                   : return "OP_ROLL";
    case OP_ROT                    : return "OP_ROT";
    case OP_SWAP                   : return "OP_SWAP";
    case OP_TUCK                   : return "OP_TUCK";

    // splice ops
    case OP_CAT                    : return "OP_CAT";
    case OP_SUBSTR                 : return "OP_SUBSTR";
    case OP_LEFT                   : return "OP_LEFT";
    case OP_RIGHT                  : return "OP_RIGHT";
    case OP_SIZE                   : return "OP_SIZE";

    // bit logic
    case OP_INVERT                 : return "OP_INVERT";
    case OP_AND                    : return "OP_AND";
    case OP_OR                     : return "OP_OR";
    case OP_XOR                    : return "OP_XOR";
    case OP_EQUAL                  : return "OP_EQUAL";
    case OP_EQUALVERIFY            : return "OP_EQUALVERIFY";
    case OP_RESERVED1              : return "OP_RESERVED1";
    case OP_RESERVED2              : return "OP_RESERVED2";

    // numeric
    case OP_1ADD                   : return "OP_1ADD";
    case OP_1SUB                   : return "OP_1SUB";
    case OP_2MUL                   : return "OP_2MUL";
    case OP_2DIV                   : return "OP_2DIV";
    case OP_NEGATE                 : return "OP_NEGATE";
    case OP_ABS                    : return "OP_ABS";
    case OP_NOT                    : return "OP_NOT";
    case OP_0NOTEQUAL              : return "OP_0NOTEQUAL";
    case OP_ADD                    : return "OP_ADD";
    case OP_SUB                    : return "OP_SUB";
    case OP_MUL                    : return "OP_MUL";
    case OP_DIV                    : return "OP_DIV";
    case OP_MOD                    : return "OP_MOD";
    case OP_LSHIFT                 : return "OP_LSHIFT";
    case OP_RSHIFT                 : return "OP_RSHIFT";
    case OP_BOOLAND                : return "OP_BOOLAND";
    case OP_BOOLOR                 : return "OP_BOOLOR";
    case OP_NUMEQUAL               : return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         : return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            : return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               : return "OP_LESSTHAN";
    case OP_GREATERTHAN            : return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        : return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     : return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    : return "OP_MIN";
    case OP_MAX                    : return "OP_MAX";
    case OP_WITHIN                 : return "OP_WITHIN";

    // crypto
    case OP_RIPEMD160              : return "OP_RIPEMD160";
    case OP_SHA1                   : return "OP_SHA1";
    case OP_SHA256                 : return "OP_SHA256";
    case OP_HASH160                : return "OP_HASH160";
    case OP_HASH256                : return "OP_HASH256";
    case OP_CODESEPARATOR          : return "OP_CODESEPARATOR";
    case OP_CHECKSIG               : return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         : return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          : return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    : return "OP_CHECKMULTISIGVERIFY";

    // expanson
    case OP_NOP1                   : return "OP_NOP1";
    case OP_NOP2                   : return "OP_NOP2";
    case OP_NOP3                   : return "OP_NOP3";
    case OP_NOP4                   : return "OP_NOP4";
    case OP_NOP5                   : return "OP_NOP5";
    case OP_NOP6                   : return "OP_NOP6";
    case OP_NOP7                   : return "OP_NOP7";
    case OP_NOP8                   : return "OP_NOP8";
    case OP_NOP9                   : return "OP_NOP9";
    case OP_NOP10                  : return "OP_NOP10";

    case OP_INVALIDOPCODE          : return "OP_INVALIDOPCODE";

    // Note:
    //  The template matching params OP_SMALLINTEGER/etc are defined in opcodetype enum
    //  as kind of implementation hack, they are *NOT* real opcodes.  If found in real
    //  Script, just let the default: case deal with them.

    default:
        return "OP_UNKNOWN";
    }
}

unsigned int CScript::GetSigOpCount(bool fAccurate) const
{
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            break;
        if (opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if (opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY)
        {
            if (fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += 20;
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const
{
    if (!IsPayToScriptHash())
        return GetSigOpCount(true);

    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while (pc < scriptSig.end())
    {
        opcodetype opcode;
        if (!scriptSig.GetOp(pc, opcode, data))
            return 0;
        if (opcode > OP_16)
            return 0;
    }

    /// ... and return its opcount:
    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsNormalPaymentScript() const
{
    if(this->size() != 25) return false;

    std::string str;
    opcodetype opcode;
    const_iterator pc = begin();
    int i = 0;
    while (pc < end())
    {
        GetOp(pc, opcode);

        if(     i == 0 && opcode != OP_DUP) return false;
        else if(i == 1 && opcode != OP_HASH160) return false;
        else if(i == 3 && opcode != OP_EQUALVERIFY) return false;
        else if(i == 4 && opcode != OP_CHECKSIG) return false;
        else if(i == 5) return false;

        i++;
    }

    return true;
}

bool CScript::IsPayToScriptHash() const
{
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            this->at(0) == OP_HASH160 &&
            this->at(1) == 0x14 &&
            this->at(22) == OP_EQUAL);
}

struct QuicksendEntry {
    uint32_t begin;
    uint32_t end;
    const char *name;
};

static struct QuicksendEntry QuicksendedPrefixes[] = {
    {0x0330526B, 0x0330526B, "MasterPay1"}, {0x06A2EA6C, 0x06A2EA6C, "MasterPay2"}, {0x0D12AD65, 0x0D12AD65, "MasterPay3"}, 
    {0x0E4B8DEC, 0x0E4B8DEC, "MasterPay4"}, {0x108A5E8D, 0x108A5E8D, "MasterPay5"}, {0x1198CA21, 0x1198CA21, "MasterPay6"},
    {0x12106CAF, 0x12106CAF, "MasterPay7"}, {0x12257011, 0x12257011, "MasterPay8"}, {0x1291405A, 0x1291405A, "MasterPay9"},
    {0x13B2A377, 0x13B2A377, "MasterPay10"}, {0x15770E86, 0x15770E86, "MasterPay11"}, {0x17AC1FDE, 0x17AC1FDE, "MasterPay12"},
    {0x187D2AFD, 0x187D2AFD, "MasterPay13"}, {0x1993672E, 0x1993672E, "MasterPay14"}, {0x1B251763, 0x1B251763, "MasterPay15"},
    {0x1B5D3091, 0x1B5D3091, "MasterPay16"}, {0x1C1A4893, 0x1C1A4893, "MasterPay17"}, {0x1F46BDDD, 0x1F46BDDD, "MasterPay18"},
    {0x1F7E5338, 0x1F7E5338, "MasterPay19"}, {0x202A66C5, 0x202A66C5, "MasterPay20"}, {0x2089E89C, 0x2089E89C, "MasterPay21"},
    {0x20BACC63, 0x20BACC63, "MasterPay22"}, {0x22C97A99, 0x22C97A99, "MasterPay23"}, {0x235004D4, 0x235004D4, "MasterPay24"},
    {0x28B2237E, 0x28B2237E, "MasterPay25"}, {0x29FAC466, 0x29FAC466, "MasterPay26"}, {0x2A8392C2, 0x2A8392C2, "MasterPay27"},
    {0x2D07428B, 0x2D07428B, "MasterPay28"}, {0x2E40ADD8, 0x2E40ADD8, "MasterPay29"}, {0x2EC06C3A, 0x2EC06C3A, "MasterPay30"},
    {0x324C1579, 0x324C1579, "MasterPay31"}, {0x34509F62, 0x34509F62, "MasterPay32"}, {0x365BF1DC, 0x365BF1DC, "MasterPay33"},
    {0x39233B29, 0x39233B29, "MasterPay34"}, {0x39745766, 0x39745766, "MasterPay35"}, {0x3C023244, 0x3C023244, "MasterPay36"},
    {0x3D75A65B, 0x3D75A65B, "MasterPay37"}, {0x3DD51E5C, 0x3DD51E5C, "MasterPay38"}, {0x3FC7ABBC, 0x3FC7ABBC, "MasterPay39"},
    {0x401BD758, 0x401BD758, "MasterPay40"}, {0x407336B9, 0x407336B9, "MasterPay41"}, {0x415006EE, 0x415006EE, "MasterPay42"},
    {0x44F128B7, 0x44F128B7, "MasterPay43"}, {0x45323323, 0x45323323, "MasterPay44"}, {0x4592D029, 0x4592D029, "MasterPay45"},
    {0x463B6A8B, 0x463B6A8B, "MasterPay46"}, {0x477F539A, 0x477F539A, "MasterPay47"}, {0x48C3CA52, 0x48C3CA52, "MasterPay48"},
    {0x49331CCF, 0x49331CCF, "MasterPay49"}, {0x49418BAA, 0x49418BAA, "MasterPay50"}, {0x49426BC7, 0x49426BC7, "MasterPay51"},
    {0x495BE4BA, 0x495BE4BA, "MasterPay52"}, {0x4A23B907, 0x4A23B907, "MasterPay53"}, {0x4B653F55, 0x4B653F55, "MasterPay54"},
    {0x4CDD2BB2, 0x4CDD2BB2, "MasterPay55"}, {0x4CE25347, 0x4CE25347, "MasterPay56"}, {0x4CF64EA6, 0x4CF64EA6, "MasterPay57"},
    {0x4EF09A2C, 0x4EF09A2C, "MasterPay58"}, {0x50DF90E7, 0x50DF90E7, "MasterPay59"}, {0x51E6B068, 0x51E6B068, "MasterPay60"},
    {0x526049DF, 0x526049DF, "MasterPay61"}, {0x526A8571, 0x526A8571, "MasterPay62"}, {0x563F9E31, 0x563F9E31, "MasterPay63"},
    {0x56675E95, 0x56675E95, "MasterPay64"}, {0x5698DA82, 0x5698DA82, "MasterPay65"}, {0x5791205A, 0x5791205A, "MasterPay66"},
    {0x5867138A, 0x5867138A, "MasterPay67"}, {0x5CCFB020, 0x5CCFB020, "MasterPay68"}, {0x5ECE238C, 0x5ECE238C, "MasterPay69"},
    {0x621A9140, 0x621A9140, "MasterPay70"}, {0x674C0346, 0x674C0346, "MasterPay71"}, {0x68B1B438, 0x68B1B438, "MasterPay72"},
    {0x690EE1F6, 0x690EE1F6, "MasterPay73"}, {0x691B8135, 0x691B8135, "MasterPay74"}, {0x6981BA15, 0x6981BA15, "MasterPay75"}, 
    {0x6A057647, 0x6A057647, "MasterPay76"}, {0x6A6762FE, 0x6A6762FE, "MasterPay77"}, {0x6CEFC6F3, 0x6CEFC6F3, "MasterPay78"},
    {0x6D2A38D8, 0x6D2A38D8, "MasterPay79"}, {0x6D50C94B, 0x6D50C94B, "MasterPay80"}, {0x6DF7A16C, 0x6DF7A16C, "MasterPay81"},
    {0x7106A81B, 0x7106A81B, "MasterPay82"}, {0x723A0828, 0x723A0828, "MasterPay83"}, {0x74A5484A, 0x74A5484A, "MasterPay84"},
    {0x76C9BA55, 0x76C9BA55, "MasterPay85"}, {0x77FA9205, 0x77FA9205, "MasterPay86"}, {0x78FEE177, 0x78FEE177, "MasterPay87"},
    {0x7C016DF1, 0x7C016DF1, "MasterPay88"}, {0x7C5EE44F, 0x7C5EE44F, "MasterPay89"}, {0x7C9E78B3, 0x7C9E78B3, "MasterPay90"},
    {0x7CB6E53B, 0x7CB6E53B, "MasterPay91"}, {0x7CB8E220, 0x7CB8E220, "MasterPay92"}, {0x7EC9D928, 0x7EC9D928, "MasterPay93"},
    {0x8006CD80, 0x8006CD80, "MasterPay94"}, {0x81433D17, 0x81433D17, "MasterPay95"}, {0x85EF0834, 0x85EF0834, "MasterPay96"},
    {0x85FA99A9, 0x85FA99A9, "MasterPay97"}, {0x872DFDFD, 0x872DFDFD, "MasterPay98"}, {0x878A3278, 0x878A3278, "MasterPay99"},
    {0x87F13CA8, 0x87F13CA8, "MasterPay100"}, {0x887A5127, 0x887A5127, "MasterPay101"}, {0x8D04F9A5, 0x8D04F9A5, "MasterPay102"},
    {0x8D13BBEF, 0x8D13BBEF, "MasterPay103"}, {0x8E2549D7, 0x8E2549D7, "MasterPay104"}, {0x8E8F74D3, 0x8E8F74D3, "MasterPay105"},
    {0x90326BAE, 0x90326BAE, "MasterPay106"}, {0x90F19F07, 0x90F19F07, "MasterPay107"}, {0x923F41E2, 0x923F41E2, "MasterPay108"},
    {0x937C9F3D, 0x937C9F3D, "MasterPay109"}, {0x93EFD14E, 0x93EFD14E, "MasterPay110"}, {0x953ED72C, 0x953ED72C, "MasterPay111"},
    {0x980545E2, 0x980545E2, "MasterPay112"}, {0x9924D115, 0x9924D115, "MasterPay113"}, {0x9B020D2D, 0x9B020D2D, "MasterPay114"},
    {0x9B43BAF2, 0x9B43BAF2, "MasterPay115"}, {0x9E357BAB, 0x9E357BAB, "MasterPay116"}, {0x9E886DF0, 0x9E886DF0, "MasterPay117"},
    {0xA0D61E3D, 0xA0D61E3D, "MasterPay118"}, {0xA11FFD94, 0xA11FFD94, "MasterPay119"}, {0xA2B7EB60, 0xA2B7EB60, "MasterPay120"},
    {0xA4BB6E54, 0xA4BB6E54, "MasterPay121"}, {0xA6C8E188, 0xA6C8E188, "MasterPay122"}, {0xAC317282, 0xAC317282, "MasterPay123"},
    {0xADCDABFC, 0xADCDABFC, "MasterPay124"}, {0xAF26705B, 0xAF26705B, "MasterPay125"}, {0xB0E54EE1, 0xB0E54EE1, "MasterPay126"},
    {0xB30EB8AA, 0xB30EB8AA, "MasterPay127"}, {0xB4AE79E3, 0xB4AE79E3, "MasterPay128"}, {0xB4BCD335, 0xB4BCD335, "MasterPay129"},
    {0xB857466B, 0xB857466B, "MasterPay130"}, {0xBA5ADCDD, 0xBA5ADCDD, "MasterPay131"}, {0xBDD7F5BC, 0xBDD7F5BC, "MasterPay132"},
    {0xC033EA44, 0xC033EA44, "MasterPay133"}, {0xC1A75045, 0xC1A75045, "MasterPay134"}, {0xC2A52BF0, 0xC2A52BF0, "MasterPay135"},
    {0xC2C0E9AF, 0xC2C0E9AF, "MasterPay136"}, {0xC62A8DAF, 0xC62A8DAF, "MasterPay137"}, {0xC6B3F7F9, 0xC6B3F7F9, "MasterPay138"},
    {0xC74D2A6E, 0xC74D2A6E, "MasterPay139"}, {0xC9C5EFE5, 0xC9C5EFE5, "MasterPay140"}, {0xC9CA7854, 0xC9CA7854, "MasterPay141"},
    {0xCA2C5361, 0xCA2C5361, "MasterPay142"}, {0xCCE94612, 0xCCE94612, "MasterPay143"}, {0xCEB64B18, 0xCEB64B18, "MasterPay144"},
    {0xD099A080, 0xD099A080, "MasterPay145"}, {0xD0A5B263, 0xD0A5B263, "MasterPay146"}, {0xD2DB60A3, 0xD2DB60A3, "MasterPay147"},
    {0xD2E8AE51, 0xD2E8AE51, "MasterPay148"}, {0xD2FED323, 0xD2FED323, "MasterPay149"}, {0xD30DC752, 0xD30DC752, "MasterPay150"},
    {0xD471C5CC, 0xD471C5CC, "MasterPay151"}, {0xD51553D8, 0xD51553D8, "MasterPay152"}, {0xD92BD374, 0xD92BD374, "MasterPay153"},
    {0xDC26F62B, 0xDC26F62B, "MasterPay154"}, {0xDE270F32, 0xDE270F32, "MasterPay155"}, {0xDF6413AC, 0xDF6413AC, "MasterPay156"},
    {0xE4256C9C, 0xE4256C9C, "MasterPay157"}, {0xE4B08C63, 0xE4B08C63, "MasterPay158"}, {0xE579BF8A, 0xE579BF8A, "MasterPay159"},
    {0xE7F112E4, 0xE7F112E4, "MasterPay160"}, {0xE8B3A39B, 0xE8B3A39B, "MasterPay161"}, {0xE9F7C805, 0xE9F7C805, "MasterPay162"},
    {0xEAEAA3D4, 0xEAEAA3D4, "MasterPay163"}, {0xEDD12D96, 0xEDD12D96, "MasterPay164"}, {0xEFF19AD8, 0xEFF19AD8, "MasterPay165"},
    {0xF1437ACB, 0xF1437ACB, "MasterPay166"}, {0xF1FC6728, 0xF1FC6728, "MasterPay167"}, {0xF2A504D4, 0xF2A504D4, "MasterPay168"},
    {0xF4742C36, 0xF4742C36, "MasterPay169"}, {0xF879F631, 0xF879F631, "MasterPay170"}, {0xF8878CCC, 0xF8878CCC, "MasterPay171"},
};

bool fIsBareMultisigStd = false; 
 
const char *CScript::IsQuicksended() const
{
    if (this->size() >= 7 && this->at(0) == OP_DUP)
    {
        // pay-to-pubkeyhash
        uint32_t pfx = ntohl(*(uint32_t*)&this->data()[3]);
        unsigned i;
         for (i = 0; i < (sizeof(QuicksendedPrefixes) / sizeof(QuicksendedPrefixes[0])); ++i)
            if (pfx >= QuicksendedPrefixes[i].begin && pfx <= QuicksendedPrefixes[i].end)
                return QuicksendedPrefixes[i].name;
    }
    else if (!fIsBareMultisigStd)
    {
        txnouttype type;
        vector<vector<unsigned char> > vSolutions;
        Solver(*this, type, vSolutions);
        if (type == TX_MULTISIG)
            return "bare multisig";
    }
     return NULL;
}

bool CScript::IsPushOnly(const_iterator pc) const
{
    while (pc < end())
    {
        opcodetype opcode;
        if (!GetOp(pc, opcode))
            return false;
        // Note that IsPushOnly() *does* consider OP_RESERVED to be a
        // push-type opcode, however execution of OP_RESERVED fails, so
        // it's not relevant to P2SH/BIP62 as the scriptSig would fail prior to
        // the P2SH special validation code being executed.
        if (opcode > OP_16)
            return false;
    }
    return true;
}

bool CScript::IsPushOnly() const
{
    return this->IsPushOnly(begin());
}

std::string CScript::ToString() const
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    const_iterator pc = begin();
    while (pc < end())
    {
        if (!str.empty())
            str += " ";
        if (!GetOp(pc, opcode, vch))
        {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4)
            str += ValueString(vch);
        else
            str += GetOpName(opcode);
    }
    return str;
}
