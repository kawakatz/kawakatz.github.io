# Theme assets bypass exclude; the root worker replaces Chirpy at the same URL.
Jekyll::Hooks.register :site, :post_read do |site|
  site.pages.reject! { |page| page.relative_path == 'assets/js/dist/sw.min.js' }
end
