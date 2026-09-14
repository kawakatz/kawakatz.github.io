require 'json'
require 'nokogiri'
require 'pathname'

root = Pathname.new(__dir__).parent
site = root.join('_site')
notes = JSON.parse(site.join('assets/notes.json').read)
raise 'No published notes in search index' if notes.empty?
home = Nokogiri::HTML(site.join('index.html').read)
raise 'Legacy cache retirement worker must replace the theme worker' unless site.join('sw.min.js').read == root.join('sw.min.js').read
raise 'Homepage must contain only the desk scene' unless home.css('main > section').size == 1 && home.at_css('main > .desk-stage')
raise 'Homepage must not display a footer' unless home.css('.site-footer').empty?
preview = home.at_css('#notes-preview')
raise 'Notes preview must load the real notebook page' unless preview&.[]('src') == '/notes/' && !preview['title'].to_s.empty? && preview['tabindex'] == '-1'
browser = home.at_css('#notes-browser')
raise 'Notes preview must start hidden and inert' unless browser&.attribute('hidden') && browser.attribute('inert') && browser['aria-hidden'] == 'true'
notebook = Nokogiri::HTML(site.join('notes/index.html').read)
raise 'Notes sharing description must match its visible introduction' unless notebook.at_css('meta[property="og:description"]')['content'] == notebook.at_css('.notebook-heading p').text
%w[notes others about].each do |slug|
  page = Nokogiri::HTML(site.join(slug, 'index.html').read)
  raise "Static page classified as an article: #{slug}" unless page.at_css('meta[property="og:type"]')['content'] == 'website'
  raise "Static page has an invented publication date: #{slug}" unless page.css('meta[property="article:published_time"], meta[property="article:modified_time"]').empty?
  metadata = JSON.parse(page.at_css('script[type="application/ld+json"]').text)
  raise "Static page schema is not WebPage: #{slug}" unless metadata['@type'] == 'WebPage' && !metadata.key?('datePublished') && !metadata.key?('dateModified')
end
[home, notebook, *%w[others about].map { |slug| Nokogiri::HTML(site.join(slug, 'index.html').read) }].zip(['Masahiro Kawada', 'Notes', 'Others', 'About']).each do |page, title|
  raise "Sharing title repeats the site name: #{title}" unless page.at_css('meta[property="og:site_name"]')['content'] == 'kawakatz.io' && page.at_css('meta[property="og:title"]')['content'] == title
  raise "Missing shared wordmark: #{title}" unless page.at_css('meta[property="og:image"]')&.[]('content') == 'https://kawakatz.io/assets/img/social/wordmark.png' && site.join('assets/img/social/wordmark.png').file?
end
raise 'Notebook footer must contain only the copyright' unless notebook.at_css('.site-footer')&.text&.strip&.match?(/\A© \d{4} kawakatz\z/) && notebook.css('.site-footer a').empty?
notebook_links = notebook.css('.note-list .note-link').map { |a| a['href'] }
raise 'Notebook does not follow published posts' unless notebook_links.sort == notes.map { |n| n.fetch('url') }.sort
raise 'Missing non-WebGL notebook link' unless home.at_css('.site-header #nav-notes')&.[]('href') == '/notes/'
cue = home.at_css('#notes-cue')
raise 'MacBook cue must link to Notes and identify its action' unless cue&.[]('href') == '/notes/' && cue['aria-label'].include?('MacBook') && cue.text.include?('Explore notes')
raise 'Inspector labels must identify the actual devices' unless home.css('[data-focus-screen]').map(&:text) == ['Dell U4919DW', 'MouseComputer MB-K690', 'iPad Air MUUQ2J/A']
raise 'Manual screen pause controls must not be displayed' unless home.css('#toggle-screen-motion, #device-screen-motion').empty?
notes.each do |note|
  page = Nokogiri::HTML(site.join(note.fetch('url').delete_prefix('/'), 'index.html').read)
  raise "Missing title: #{note['url']}" unless page.at_css('h1')&.text == note.fetch('title')
  raise "Missing content: #{note['url']}" unless page.at_css('#article-content')&.text&.length.to_i > 100
  page.css('#article-content img').each do |image|
    raise "Article image must use a figure and preserve its explicit width: #{image['src']}" unless image.parent.name == 'figure' && image['width'].to_i.positive?
  end
  raise "Image captions must belong to a figure: #{note['url']}" unless page.css('#article-content figcaption').all? { |caption| caption.parent.name == 'figure' }
  raise "3D loaded in article: #{note['url']}" if page.css('script[src]').any? { |s| s['src'].end_with?('/desk.js') }
  raise "Missing dates: #{note['url']}" if page.css('.article-meta time[datetime]').empty?
  raise "Article publication metadata missing: #{note['url']}" unless page.at_css('meta[property="og:type"]')['content'] == 'article' && page.at_css('meta[property="article:published_time"]')
  raise "Missing search content: #{note['url']}" if note.fetch('body').length < 100
end
raise 'Original Others route missing' unless site.join('others/index.html').file?
raise 'RSS missing' unless site.join('feed.xml').file?
puts "Verified #{notes.size} full articles, stable routes, search data, dates, Others, and RSS"
