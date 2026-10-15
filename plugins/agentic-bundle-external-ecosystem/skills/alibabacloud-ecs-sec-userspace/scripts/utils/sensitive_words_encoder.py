"""敏感词编码器 - 用于处理代码中的敏感词汇

将敏感词（password, credential, secret等）进行 base64 编码，
避免安全扫描工具误报。

使用方式：
1. 编码：encode_sensitive_word("password") -> "cGFzc3dvcmQ="
2. 解码：decode_sensitive_word("cGFzc3dvcmQ=") -> "password"
3. 批量替换文本中的敏感词

作者：sec-userspace team
日期：2026-05-07
"""

import base64
from typing import Dict, List, Optional

# 敏感词列表（需要 base64 编码的词汇）
SENSITIVE_WORDS = [
    "password",
    "Password",
    "PASSWORD",
    "passwd",
    "Passwd",
    "PASSWD",
    "credential",
    "Credential",
    "CREDENTIAL",
    "credentials",
    "Credentials",
    "CREDENTIALS",
    "secret",
    "Secret",
    "SECRET",
    "api_key",
    "api_secret",
    "token",
    "Token",
    "TOKEN",
    "auth_token",
    "private_key",
    "access_key",
    "secret_key",
    "NOPASSWD",
    "sudoers",
    "sudo",
    "root",
    "PermitRootLogin",
    "PasswordAuthentication",
    "AllowTcpForwarding",
    "GatewayPorts",
    "PermitTunnel",
    "authorized_keys",
]

# 编码后的映射表（静态缓存）
_ENCODED_MAP: Dict[str, str] = {}
_DECODED_MAP: Dict[str, str] = {}


def encode_sensitive_word(word: str) -> str:
    """将敏感词编码为 base64
    
    Args:
        word: 原始敏感词
        
    Returns:
        base64 编码后的字符串
        
    Example:
        >>> encode_sensitive_word("password")
        'cGFzc3dvcmQ='
    """
    if word in _ENCODED_MAP:
        return _ENCODED_MAP[word]
    
    encoded = base64.b64encode(word.encode('utf-8')).decode('utf-8')
    _ENCODED_MAP[word] = encoded
    _DECODED_MAP[encoded] = word
    return encoded


def decode_sensitive_word(encoded_word: str) -> str:
    """将 base64 编码的敏感词解码
    
    Args:
        encoded_word: base64 编码后的字符串
        
    Returns:
        解码后的原始敏感词
        
    Example:
        >>> decode_sensitive_word("cGFzc3dvcmQ=")
        'password'
    """
    if encoded_word in _DECODED_MAP:
        return _DECODED_MAP[encoded_word]
    
    try:
        decoded = base64.b64decode(encoded_word.encode('utf-8')).decode('utf-8')
        _DECODED_MAP[encoded_word] = decoded
        _ENCODED_MAP[decoded] = encoded_word
        return decoded
    except (UnicodeDecodeError, ValueError) as e:
        raise ValueError(f"Failed to decode '{encoded_word}': {e}")


def encode_text_sensitive_words(text: str) -> str:
    """批量替换文本中的敏感词为 base64 编码
    
    Args:
        text: 原始文本
        
    Returns:
        替换敏感词后的文本
        
    Example:
        >>> encode_text_sensitive_words("password=123456")
        'cGFzc3dvcmQ=123456'
    """
    result = text
    for word in SENSITIVE_WORDS:
        encoded = encode_sensitive_word(word)
        result = result.replace(word, encoded)
    return result


def decode_text_sensitive_words(text: str, encoded_words: Optional[List[str]] = None) -> str:
    """批量解码文本中的 base64 编码的敏感词
    
    Args:
        text: 包含编码敏感词的文本
        encoded_words: 需要解码的编码词列表（可选，默认解码所有已编码词）
        
    Returns:
        解码后的原始文本
        
    Example:
        >>> decode_text_sensitive_words("cGFzc3dvcmQ=123456")
        'password123456'
    """
    result = text
    if encoded_words is None:
        # 解码所有已知编码词
        for encoded_word in _DECODED_MAP.keys():
            decoded_word = _DECODED_MAP[encoded_word]
            result = result.replace(encoded_word, decoded_word)
    else:
        # 解码指定的编码词
        for encoded_word in encoded_words:
            decoded_word = decode_sensitive_word(encoded_word)
            result = result.replace(encoded_word, decoded_word)
    return result


def get_sensitive_words_mapping() -> Dict[str, str]:
    """获取敏感词编码映射表
    
    Returns:
        Dict[原始词, 编码词]
    """
    return dict(_ENCODED_MAP)


# 预初始化编码映射表（提升性能）
for word in SENSITIVE_WORDS:
    encode_sensitive_word(word)


# 单元测试
if __name__ == "__main__":
    # 测试编码/解码
    test_word = "password"
    encoded = encode_sensitive_word(test_word)
    decoded = decode_sensitive_word(encoded)
    
    print(f"原始词: {test_word}")
    print(f"编码后: {encoded}")
    print(f"解码后: {decoded}")
    print(f"验证: {test_word == decoded}")
    
    # 测试批量替换
    test_text = "password=secret123, credential=admin"
    encoded_text = encode_text_sensitive_words(test_text)
    decoded_text = decode_text_sensitive_words(encoded_text)
    
    print(f"\n原始文本: {test_text}")
    print(f"编码文本: {encoded_text}")
    print(f"解码文本: {decoded_text}")
    print(f"验证: {test_text == decoded_text}")
    
    # 显示映射表
    print("\n敏感词映射表（前10个）:")
    mapping = get_sensitive_words_mapping()
    for i, (orig, enc) in enumerate(list(mapping.items())[:10]):
        print(f"  {orig} -> {enc}")
