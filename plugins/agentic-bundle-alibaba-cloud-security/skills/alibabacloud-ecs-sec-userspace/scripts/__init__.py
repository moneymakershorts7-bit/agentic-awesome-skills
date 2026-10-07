import os
import sys

# 注入 thirdparties 本地第三方库路径（优先于系统库）
# thirdparties 现在位于 scripts/thirdparties/，与 scripts/ 一起打包进 zipapp
_init_file = os.path.abspath(__file__)
if '.pyz' in _init_file:
    # Zipapp 模式: __file__ = /path/scripts/main.pyz/scripts/__init__.py
    _pyz_part = _init_file.split('.pyz')[0] + '.pyz'
    _thirdparties_path = os.path.join(_pyz_part, "scripts", "thirdparties")
else:
    # Plain 模式: __file__ = /path/scripts/__init__.py
    _scripts_dir = os.path.dirname(_init_file)
    _thirdparties_path = os.path.join(_scripts_dir, "thirdparties")
if os.path.isdir(_thirdparties_path) and _thirdparties_path not in sys.path:
    sys.path.insert(0, _thirdparties_path)

"""sec-userspace - Linux Security Intrusion Detection Tool."""
