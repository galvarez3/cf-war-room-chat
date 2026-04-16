// Safely render a single chat message into `container`.
//
// Every user-supplied field (`author`, `text`) is written with `textContent`,
// never `innerHTML`, so a hostile Firestore document cannot inject markup or
// script. The `color` field is parsed as hex; the resulting hue is clamped
// through `Number.isFinite` so a crafted value cannot escape the `style`
// attribute.
//
// `doc` is injectable for testing under jsdom without touching the real DOM.
export function renderMessage(message, container, doc) {
  const ownerDoc =
    doc || (container && container.ownerDocument) || globalThis.document;

  const div = ownerDoc.createElement('div');
  div.classList.add('chat-message', 'border', 'border-gray-800');

  const parsedHue =
    typeof message.color === 'string' && message.color.length > 0
      ? parseInt(message.color.substring(0, 8), 16) % 360
      : 0;
  const hue = Number.isFinite(parsedHue) ? parsedHue : 0;
  const userColor = `hsl(${hue}, 80%, 65%)`;

  const timestamp =
    message.timestamp && typeof message.timestamp.seconds === 'number'
      ? new Date(message.timestamp.seconds * 1000).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
        })
      : '...';

  const header = ownerDoc.createElement('div');
  header.className =
    'flex justify-between items-center text-xs text-gray-400 mb-1';

  const authorSpan = ownerDoc.createElement('span');
  authorSpan.className = 'chat-author font-bold';
  authorSpan.style.color = userColor;
  authorSpan.textContent = message.author == null ? '' : String(message.author);

  const timeSpan = ownerDoc.createElement('span');
  timeSpan.textContent = timestamp;

  header.appendChild(authorSpan);
  header.appendChild(timeSpan);

  const body = ownerDoc.createElement('p');
  body.className = 'text-sm text-gray-200';
  body.textContent = message.text == null ? '' : String(message.text);

  div.appendChild(header);
  div.appendChild(body);

  if (container) container.appendChild(div);
  return div;
}
