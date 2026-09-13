export const ease = (t) => t < 0.5 ? 4 * t ** 3 : 1 - (-2 * t + 2) ** 3 / 2;

// Four screen corners let the HTML browser follow the physical display's perspective.
export function quadTransform([p0, p1, p2, p3], width, height) {
  const dx1 = p1.x - p2.x, dx2 = p3.x - p2.x, dx3 = p0.x - p1.x + p2.x - p3.x;
  const dy1 = p1.y - p2.y, dy2 = p3.y - p2.y, dy3 = p0.y - p1.y + p2.y - p3.y;
  const denominator = dx1 * dy2 - dx2 * dy1;
  const g = (dx3 * dy2 - dx2 * dy3) / denominator, h = (dx1 * dy3 - dx3 * dy1) / denominator;
  return [(p1.x-p0.x+g*p1.x)/width, (p1.y-p0.y+g*p1.y)/width, 0, g/width,
    (p3.x-p0.x+h*p3.x)/height, (p3.y-p0.y+h*p3.y)/height, 0, h/height,
    0, 0, 1, 0, p0.x, p0.y, 0, 1];
}

export function notesFlight(progress, dock, floating, display, viewport) {
  const p = Math.max(0, Math.min(1, progress));
  const [from, to, fraction] = p < .35 ? [dock, floating, p/.35]
    : p < .75 ? [floating, display, (p-.35)/.4] : [display, viewport, (p-.75)/.25];
  const amount = ease(fraction);
  return from.map((point, i) => ({x: point.x+(to[i].x-point.x)*amount, y: point.y+(to[i].y-point.y)*amount}));
}

export function matchesNote(note, query) {
  const haystack = `${note.title} ${note.description} ${note.body}`.normalize('NFKC').toLocaleLowerCase();
  return query.normalize('NFKC').toLocaleLowerCase().trim().split(/\s+/).every(word => haystack.includes(word));
}

export function previewPosition(anchor, preview, viewport) {
  const top = anchor.bottom + 10 + preview.height <= viewport.height - 12
    ? anchor.bottom + 10 : anchor.top - preview.height - 10;
  return {
    left: Math.max(12, Math.min(anchor.left, viewport.width - preview.width - 12)),
    top: Math.max(12, Math.min(top, viewport.height - preview.height - 12)),
  };
}
