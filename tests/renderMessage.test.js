// Regression tests for the XSS vulnerability in `renderMessage`.
//
// Before the fix, `renderMessage` interpolated `message.author` and
// `message.text` into a string that was assigned to `div.innerHTML`. Any
// Firestore document with HTML in those fields was parsed as markup, which
// is an XSS sink: an attacker joining the chat could execute arbitrary
// JavaScript in every other player's browser.
//
// These tests intentionally use real XSS payloads and assert that no
// attacker-controlled node ends up in the DOM tree and that no side-effect
// script runs. They also lock in the rendering contract (classes, timestamp
// fallback, hue math) so that future refactors don't silently regress.

import { describe, it, expect, beforeEach } from 'vitest';
import { renderMessage } from '../src/renderMessage.js';

let container;

beforeEach(() => {
  document.body.innerHTML = '<div id="chat"></div>';
  container = document.getElementById('chat');
  delete window.__hacked;
});

describe('renderMessage - XSS regressions', () => {
  it('does not parse <script> in message.text as HTML', () => {
    renderMessage(
      { author: 'evil', text: '<script>window.__hacked = true</script>' },
      container,
    );

    expect(window.__hacked).toBeUndefined();
    expect(container.querySelector('script')).toBeNull();

    const body = container.querySelector('p.text-sm');
    expect(body.textContent).toBe('<script>window.__hacked = true</script>');
  });

  it('does not fire onerror handlers embedded in message.text', () => {
    renderMessage(
      { author: 'evil', text: '<img src=x onerror="window.__hacked=true">' },
      container,
    );

    expect(window.__hacked).toBeUndefined();
    expect(container.querySelector('img')).toBeNull();
  });

  it('does not parse markup in message.author', () => {
    renderMessage(
      {
        author: '<img src=x onerror="window.__hacked=true">',
        text: 'hello',
      },
      container,
    );

    expect(window.__hacked).toBeUndefined();
    expect(container.querySelector('img')).toBeNull();

    const author = container.querySelector('.chat-author');
    expect(author.textContent).toBe(
      '<img src=x onerror="window.__hacked=true">',
    );
  });

  it('preserves special characters as visible text, not markup', () => {
    renderMessage(
      { author: 'alice', text: '<b>bold</b> & "quoted" & \'apos\'' },
      container,
    );

    const body = container.querySelector('p.text-sm');
    expect(body.textContent).toBe('<b>bold</b> & "quoted" & \'apos\'');
    expect(body.querySelector('b')).toBeNull();
  });

  it('keeps the style attribute well-formed for a hostile color field', () => {
    // A crafted `color` used to contribute to a template literal that ended up
    // inside a `style="..."` attribute. Ensure the emitted style carries only a
    // single `color` declaration and that no extra properties leak in.
    renderMessage(
      {
        author: 'alice',
        text: 'hello',
        color: 'abcdef"; background:url(javascript:alert(1)); x="',
      },
      container,
    );

    const author = container.querySelector('.chat-author');
    const styleAttr = author.getAttribute('style') || '';
    // Only a single declaration, and it must be `color`.
    const declarations = styleAttr
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean);
    expect(declarations).toHaveLength(1);
    expect(declarations[0]).toMatch(/^color:\s*\S/);
    expect(author.style.background).toBe('');
    expect(author.style.getPropertyValue('background-image')).toBe('');
  });

  it('renders multiple hostile messages without cross-contamination', () => {
    renderMessage(
      { author: 'a', text: '<script>window.__hacked=1</script>' },
      container,
    );
    renderMessage({ author: 'b', text: 'plain' }, container);

    expect(window.__hacked).toBeUndefined();
    expect(container.querySelectorAll('.chat-message')).toHaveLength(2);
    expect(container.querySelector('script')).toBeNull();
  });
});

describe('renderMessage - rendering contract', () => {
  it('falls back to "..." when timestamp is missing', () => {
    renderMessage({ author: 'a', text: 't' }, container);
    const spans = container.querySelectorAll('.chat-message > div > span');
    expect(spans[1].textContent).toBe('...');
  });

  it('falls back to "..." when timestamp.seconds is missing', () => {
    renderMessage(
      { author: 'a', text: 't', timestamp: {} },
      container,
    );
    const spans = container.querySelectorAll('.chat-message > div > span');
    expect(spans[1].textContent).toBe('...');
  });

  it('formats a valid timestamp.seconds as HH:MM', () => {
    renderMessage(
      { author: 'a', text: 't', timestamp: { seconds: 1_700_000_000 } },
      container,
    );
    const spans = container.querySelectorAll('.chat-message > div > span');
    // Locale can vary, but "..." is the only non-time fallback we should hit.
    expect(spans[1].textContent).not.toBe('...');
    expect(spans[1].textContent.length).toBeGreaterThan(0);
  });

  it('applies a color when color is missing (hue = 0 fallback)', () => {
    renderMessage({ author: 'a', text: 't' }, container);
    // jsdom serializes hsl() to rgb(), so assert the attribute is present and
    // well-formed rather than an exact hsl string.
    const style = container
      .querySelector('.chat-author')
      .getAttribute('style');
    expect(style).toMatch(/^color:\s*.+;?\s*$/);
  });

  it('uses distinct hues for distinct color inputs', () => {
    // parseInt('aabbccdd', 16) % 360 === 77
    // parseInt('11223344', 16) % 360 === 140
    const m1 = renderMessage(
      { author: 'a', text: 't', color: 'aabbccddeeee' },
      container,
    );
    const m2 = renderMessage(
      { author: 'b', text: 't', color: '11223344eeee' },
      container,
    );
    const c1 = m1.querySelector('.chat-author').getAttribute('style');
    const c2 = m2.querySelector('.chat-author').getAttribute('style');
    expect(c1).not.toBe(c2);
  });

  it('only looks at the first 8 hex chars of color (suffix is ignored)', () => {
    const a = renderMessage(
      { author: 'a', text: 't', color: '12345678aaaa' },
      container,
    );
    const b = renderMessage(
      { author: 'b', text: 't', color: '12345678bbbb' },
      container,
    );
    expect(a.querySelector('.chat-author').getAttribute('style')).toBe(
      b.querySelector('.chat-author').getAttribute('style'),
    );
  });

  it('renders an empty string when author or text are missing', () => {
    const div = renderMessage({}, container);
    expect(div.querySelector('.chat-author').textContent).toBe('');
    expect(div.querySelector('p.text-sm').textContent).toBe('');
  });

  it('appends each call to the container', () => {
    renderMessage({ author: 'a', text: '1' }, container);
    renderMessage({ author: 'b', text: '2' }, container);
    expect(container.children).toHaveLength(2);
  });

  it('returns the new message element', () => {
    const el = renderMessage({ author: 'a', text: 't' }, container);
    expect(el).toBe(container.firstChild);
    expect(el.classList.contains('chat-message')).toBe(true);
  });
});
