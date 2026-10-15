Push/drag challenge: Continuously drag an object in a direction.

**Strategy:**
1. Find the draggable object (boulder, ball, etc.) in the screenshot.
2. Drag it in the required direction — usually uphill or towards a target.
3. Repeat the drag multiple times since the object may slide back.

**Steps:**
```json
"steps": [
  {"ClickDragPoint":{"startX":OBJx,"startY":OBJy,"endX":TARGETx,"endY":TARGETy}},
  {"Wait":300},
  {"ClickDragPoint":{"startX":OBJx2,"startY":OBJy2,"endX":TARGETx,"endY":TARGETy}},
  {"Wait":300}
]
```

Repeat dragging 3-5 times per round. Object position changes after each drag.
After reaching the target, click verify. Solve in 3-6 rounds.
