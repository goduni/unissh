// Keyboard movement through a filtered list. Shared because every list that
// pairs a search box with a highlight needs the same two rules — wrap at the
// ends, and survive the list shrinking under the highlight — and two lists that
// disagreed on either would act on different rows than the ones they paint.

/** Move the highlight by `delta`, wrapping at both ends — a keyboard that stops
 *  dead at the last row makes the user reach for the mouse to get back to the
 *  first. Also the clamp for a highlight left pointing past a list that just
 *  shrank under it, which is what every keystroke does. */
export function nextRow(current: number, delta: number, count: number): number {
  if (count <= 0) return 0;
  // Out of range is not a position to step from — the arithmetic would land
  // somewhere arbitrary inside the new list. Go to the edge the key is heading for.
  if (current < 0 || current >= count) return delta >= 0 ? 0 : count - 1;
  return (((current + delta) % count) + count) % count;
}
