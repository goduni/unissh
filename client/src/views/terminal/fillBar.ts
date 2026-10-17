// Where the saved-password bar (#135) sits in a pane.

/** The edge of the pane the bar goes on: the one away from the cursor, so the
 *  prompt it is about stays in sight without resizing the terminal (a resize
 *  makes tmux and full-screen programs redraw). `cursorY` is the cursor's row
 *  in the viewport, `rows` the viewport's height. */
export function fillBarSide(cursorY: number, rows: number): "top" | "bottom" {
  return rows > 0 && cursorY >= rows / 2 ? "top" : "bottom";
}
