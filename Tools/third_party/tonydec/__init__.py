"""Vendored TonyEnc decoder by Jixun Wu (MIT)."""

from .tonydec import decrypt_content, decrypt_file, recurse_decrypt

__all__ = ["decrypt_content", "decrypt_file", "recurse_decrypt"]
