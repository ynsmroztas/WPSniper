# Drop the operator binary

The classifier lives in `WPSniper.py` (~22 KB, v1.3).

GitHub web:

1. Open https://github.com/ynsmroztas/WPSniper
2. **Add file → Upload files**
3. Drop the `WPSniper.py` from the chat attachment (overwrite the placeholder)
4. Commit to `main`

Then:

```
pip install -r requirements.txt
python3 WPSniper.py -u https://lab.wordpress.local --shell
```
