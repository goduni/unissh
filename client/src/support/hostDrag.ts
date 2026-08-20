// Dragging hosts onto a group. Two things live here, both kept out of the views
// so the Hosts screen (the drag source) and the sidebar (the drop target) cannot
// disagree about what a drag is carrying: the payload, and the one rule that
// decides what goes in it.
//
// The move itself is NOT here — `planGroupMove` / `moveHostsToGroup` already own
// what "put these hosts in this group" means, and a second implementation of the
// membership rules is exactly how drag and the menu would drift apart.

/** The hosts currently being dragged. A module ref rather than `DataTransfer`
 *  because the payload never leaves the app, and because DataTransfer's contents
 *  are unreadable during `dragover` — which is precisely when a drop target has
 *  to decide whether to light up. Same shape as the SFTP rows' `dragCtx`. */
let dragged: string[] = [];

export const hostDrag = {
  set: (profileIds: string[]) => {
    dragged = profileIds;
  },
  /** Empty when no host drag is in flight — a drop handler treats that as a
   *  no-op, which is also what an Escape-cancelled drag leaves behind. */
  get: (): string[] => dragged,
  clear: () => {
    dragged = [];
  },
};

/** Marker put on the native DataTransfer. WebKit webviews (macOS/Linux) only
 *  initiate a drag when the native data store is non-empty; the payload itself
 *  lives in `hostDrag`, this only arms the gesture. */
export const HOST_DRAG_MIME = "application/x-unissh-host";

/** Which hosts a drag carries: the whole multi-selection when the host that was
 *  picked up is part of it, otherwise just that host.
 *
 *  The second half is the point — grabbing a host OUTSIDE the selection moves
 *  only what was grabbed. Moving six unrelated hosts because they happened to
 *  still be selected is a data change the user never asked for, and one they'd
 *  have to undo by hand six times. */
export function draggedHostIds(grabbedId: string, selection: string[]): string[] {
  return selection.includes(grabbedId) ? [...selection] : [grabbedId];
}
