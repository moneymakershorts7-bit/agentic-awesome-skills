Parking challenge: Drag or steer an object into the highlighted target zone.

**Strategy:**
1. Identify the car/object and the target parking spot in the screenshot.
2. Use ClickDragPoint to drag the car from its current position INTO the parking spot.
3. Or use arrow key presses if steering controls are present.

**Drag approach:**
```json
"steps": [
  {"ClickDragPoint":{"startX":CARx,"startY":CARy,"endX":SPOTx,"endY":SPOTy}},
  {"Wait":500},
  {"Click":"#captcha-verify-button"}
]
```

**Arrow key approach:**
```json
"steps": [
  {"KeyDown":"ArrowUp"},{"Wait":200},{"KeyDown":"ArrowUp"},{"Wait":200},
  {"KeyDown":"ArrowLeft"},{"Wait":200},
  {"Click":"#captcha-verify-button"}
]
```

Look at the layout carefully. If there are steering wheel controls, click them. Solve in 3-5 rounds.
