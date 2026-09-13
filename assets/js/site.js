import { matchesNote, previewPosition } from './navigation.js';

const form = document.querySelector('.search-form');
if (form) {
  const input = form.querySelector('input');
  const status = document.querySelector('#search-status');
  const cards = [...document.querySelectorAll('[data-note]')];
  let index;
  let request;
  let revision = 0;
  // ponytail: download the static index once; use a search service if the archive becomes too large.
  async function search() {
    const current = ++revision;
    const query = input.value.trim();
    const url = new URL(location.href);
    query ? url.searchParams.set('q', query) : url.searchParams.delete('q');
    history.replaceState(null, '', url);
    if (!query) {
      cards.forEach(card => { card.hidden = false; });
      status.hidden = true;
      return;
    }
    status.hidden = false;
    status.textContent = 'Searching…';
    try {
      request ??= fetch(form.dataset.index).then(response => {
        if (!response.ok) throw new Error('Search index unavailable');
        return response.json();
      });
      index ??= await request;
      if (current !== revision) return;
      const matches = new Set(index.filter(note => matchesNote(note, query)).map(note => note.url));
      cards.forEach(card => { card.hidden = !matches.has(card.dataset.url); });
      status.textContent = matches.size ? `${matches.size} ${matches.size === 1 ? 'note' : 'notes'} found` : 'No notes found. Try another word or clear the search.';
    } catch {
      request = undefined;
      if (current !== revision) return;
      cards.forEach(card => { card.hidden = false; });
      status.textContent = 'Search could not load. All notes are shown; try again.';
    }
  }
  let timer;
  input.addEventListener('input', () => { clearTimeout(timer); revision++; timer = setTimeout(search, 150); });
  form.addEventListener('submit', event => { event.preventDefault(); clearTimeout(timer); search(); });
  input.value = new URLSearchParams(location.search).get('q') || '';
  if (input.value) search();
  if (location.hash === '#search') input.focus();
}

const prose = document.querySelector('.prose');
if (prose) {
  for (const block of prose.querySelectorAll('.highlighter-rouge')) {
    const code = block.querySelector('.rouge-code pre') || block.querySelector('pre');
    if (!code) continue;
    const tools = document.createElement('div');
    tools.className = 'code-tools';
    const label = document.createElement('span');
    const language = [...block.classList].find(name => name.startsWith('language-'))?.slice(9) || 'plaintext';
    label.textContent = ({ sh: 'Shell', powershell: 'PowerShell', registry: 'Registry', log: 'Log', plaintext: 'Plain text' })[language] || language;
    const status = document.createElement('span');
    status.className = 'code-copy-status';
    status.setAttribute('role', 'status');
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.title = 'Copy code';
    copy.setAttribute('aria-label', `Copy ${label.textContent} code`);
    copy.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><g class="copy-symbol"><rect x="8" y="3" width="8" height="4" rx="1"/><path d="M8 5H6a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1h-2"/></g><path class="copy-check" d="m5 12 4 4L19 6"/></svg>';
    let reset;
    copy.addEventListener('click', async () => {
      clearTimeout(reset);
      copy.disabled = true;
      delete copy.dataset.state;
      status.textContent = '';
      try {
        await navigator.clipboard.writeText(code.textContent);
        copy.dataset.state = 'copied';
        status.textContent = 'Copied';
      } catch {
        copy.dataset.state = 'error';
        status.textContent = 'Select and copy manually';
      } finally {
        copy.disabled = false;
        reset = setTimeout(() => {
          delete copy.dataset.state;
          status.textContent = '';
        }, copy.dataset.state === 'error' ? 4000 : 2200);
      }
    });
    tools.append(label, status, copy);
    block.prepend(tools);
  }
  for (const table of prose.querySelectorAll('table:not(.rouge-table)')) {
    if (table.closest('.highlight')) continue;
    const wrapper = document.createElement('div');
    wrapper.className = 'table-wrapper';
    table.before(wrapper);
    wrapper.append(table);
  }
}

const previewLinks = document.querySelectorAll('.work-entry a[data-preview]');
if (previewLinks.length) {
  const preview = document.createElement('div');
  preview.className = 'work-link-preview';
  preview.id = 'work-link-preview';
  preview.setAttribute('role', 'tooltip');
  preview.hidden = true;
  const image = document.createElement('img');
  image.alt = '';
  image.decoding = 'async';
  const meta = document.createElement('small');
  const title = document.createElement('p');
  preview.append(image, meta, title);
  document.body.append(preview);
  let active, opening, closing;
  const hide = () => {
    clearTimeout(opening);
    clearTimeout(closing);
    preview.hidden = true;
    active?.removeAttribute('aria-describedby');
    active = undefined;
  };
  const position = () => {
    const point = previewPosition(active.getBoundingClientRect(), preview.getBoundingClientRect(), { width: innerWidth, height: innerHeight });
    preview.style.left = `${point.left}px`;
    preview.style.top = `${point.top}px`;
  };
  const show = link => {
    hide();
    active = link;
    meta.textContent = link.dataset.preview;
    title.textContent = link.textContent.replace(/\s*↗\s*$/, '').trim();
    image.hidden = !link.dataset.previewImage;
    if (link.dataset.previewImage) image.src = link.dataset.previewImage;
    preview.hidden = false;
    position();
    link.setAttribute('aria-describedby', preview.id);
  };
  const leave = () => {
    clearTimeout(opening);
    clearTimeout(closing);
    closing = setTimeout(() => {
      if (!active?.matches(':hover, :focus-visible') && !preview.matches(':hover')) hide();
    }, 150);
  };
  for (const link of previewLinks) {
    link.addEventListener('pointerenter', event => {
      if (event.pointerType === 'touch') return;
      clearTimeout(opening);
      clearTimeout(closing);
      opening = setTimeout(() => show(link), 150);
    });
    link.addEventListener('pointerleave', leave);
    link.addEventListener('focus', () => { if (link.matches(':focus-visible')) show(link); });
    link.addEventListener('blur', leave);
    link.addEventListener('click', hide);
  }
  preview.addEventListener('pointerenter', () => clearTimeout(closing));
  preview.addEventListener('pointerleave', leave);
  image.addEventListener('error', () => { image.hidden = true; if (active) position(); });
  document.addEventListener('keydown', event => { if (event.key === 'Escape') hide(); });
  window.addEventListener('scroll', hide);
  window.addEventListener('resize', hide);
}

const lightbox = document.querySelector('.image-lightbox');
if (lightbox) {
  const closeButton = lightbox.querySelector('.lightbox-close');
  const enlarged = document.createElement('img');
  enlarged.className = 'lightbox-image';
  closeButton.append(enlarged);
  let trigger, zoom, backdrop;
  let opening = false, closing = false;
  const close = async () => {
    if (!lightbox.open || closing) return;
    closing = true;
    zoom?.reverse();
    backdrop?.reverse();
    await zoom?.finished.catch(() => {});
    lightbox.close();
  };
  for (const [index, image] of [...document.querySelectorAll('#article-content img')].entries()) {
    if (image.closest('a, button')) continue;
    const label = image.alt.trim() || `Image ${index + 1}`;
    image.tabIndex = 0;
    image.setAttribute('role', 'button');
    image.setAttribute('aria-label', `Enlarge ${label}`);
    image.setAttribute('aria-haspopup', 'dialog');
    image.classList.add('image-zoom');
    const open = async () => {
      if (lightbox.open || opening) return;
      opening = true;
      trigger = image;
      enlarged.src = image.currentSrc || image.src;
      enlarged.alt = label;
      try { await enlarged.decode(); }
      catch { opening = false; return; }
      opening = false;
      const from = image.getBoundingClientRect();
      lightbox.showModal();
      const to = enlarged.getBoundingClientRect();
      image.classList.add('is-zoomed');
      if (!matchMedia('(prefers-reduced-motion: reduce)').matches) {
        const timing = { duration: 300, easing: 'cubic-bezier(.2, 0, .2, 1)', fill: 'both' };
        zoom = enlarged.animate([
          { transform: `translate(${from.x - to.x}px, ${from.y - to.y}px) scale(${from.width / to.width}, ${from.height / to.height})` },
          { transform: 'none' }
        ], timing);
        backdrop = lightbox.animate({ backgroundColor: ['#ffffff00', '#fff'] }, timing);
      }
    };
    image.addEventListener('click', open);
    image.addEventListener('keydown', event => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      open();
    });
  }
  closeButton.addEventListener('click', close);
  lightbox.addEventListener('click', event => { if (event.target === lightbox) close(); });
  lightbox.addEventListener('cancel', event => { event.preventDefault(); close(); });
  lightbox.addEventListener('close', () => {
    zoom?.cancel();
    backdrop?.cancel();
    zoom = backdrop = undefined;
    closing = false;
    trigger?.classList.remove('is-zoomed');
    trigger?.focus({ preventScroll: true });
  });
}

const toc = document.querySelector('#toc-links');
if (toc) {
  const headings = [...document.querySelectorAll('#article-content h2[id], #article-content h3[id]')];
  const links = new Map();
  for (const heading of headings) {
    const link = document.createElement('a');
    link.href = `#${heading.id}`;
    link.textContent = heading.textContent;
    link.dataset.level = heading.tagName.slice(1);
    links.set(heading.id, link);
    toc.append(link);
  }
  toc.closest('aside').hidden = headings.length === 0;
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) if (entry.isIntersecting) {
      for (const link of links.values()) link.removeAttribute('aria-current');
      links.get(entry.target.id).setAttribute('aria-current', 'location');
    }
  }, { rootMargin: '-5% 0px -65% 0px' });
  headings.forEach(heading => observer.observe(heading));
}
