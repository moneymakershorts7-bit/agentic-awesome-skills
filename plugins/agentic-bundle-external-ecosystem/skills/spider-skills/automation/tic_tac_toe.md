Tic-tac-toe (XOXO): Board state is tracked across rounds. Moves are auto-made via dispatchEvent.
Read `document.title` for result. M = my mark, T = opponent mark, . = empty.

**Ignore image-grid-selection skill -- this is NOT an image grid.**

Title format: `TTT:{"n":9,"board":"M..T.M..T","best":4,"clicked":true,"myWin":false,"thWin":false,"full":false}`

**Rules (check title EVERY round):**
- **myWin is true** -> we won! Click verify: `[{"Click":"#captcha-verify-button"}]`
- **thWin is true** -> opponent won, refresh: `[{"Click":".captcha-refresh"},{"Wait":800}]`
- **clicked is true, no winner** -> wait for opponent: `[{"Wait":800}]`
- **full is true, no winner** -> draw, refresh: `[{"Click":".captcha-refresh"},{"Wait":800}]`
- **best is -1, not full** -> wait for state: `[{"Wait":800}]`
- **n != 9 or TTT_ERR** -> board not ready, wait: `[{"Wait":1000}]`

**Do NOT write any Evaluate JS or use ClickPoint. Moves are made automatically.**
