require 'jekyll'
require 'tmpdir'
require_relative '../_plugins/link-icons'

converter = ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, 'magick')) } ? 'magick' : 'convert'
png, error, status = Open3.capture3(converter, '-size', '32x24', 'xc:white', '-fill', '#123456', '-draw', 'rectangle 6,5 25,18', 'png:-', binmode: true)
raise error unless status.success?
transparent, error, status = Open3.capture3(converter, '-size', '32x24', 'xc:none', '-fill', '#654321', '-draw', 'rectangle 6,5 25,18', 'png:-', binmode: true)
raise error unless status.success?
svg = File.binread(File.expand_path('../assets/icons/social/x.svg', __dir__))
globe = File.binread(File.expand_path('../assets/icons/links/globe.svg', __dir__))
jpeg = File.binread(File.expand_path('../assets/img/avatar/kawakatz.jpg', __dir__))
calls = Hash.new(0)
original_download = LinkIcons.method(:download)
LinkIcons.define_singleton_method(:download) do |url, _redirects = 4|
  uri = URI(url)
  if uri.host == 'trustedsec.com'
    raise 'TrustedSec must use its declared favicon' unless url == 'https://trustedsec.com/favicons/favicon-32x32.png'
    calls[uri.host] += 1
    next transparent
  end
  query = URI.decode_www_form(uri.query).to_h
  raise 'Unexpected favicon provider or size' unless uri.host == 'www.google.com' && query['sz'] == '64'
  target = URI(query.fetch('domain_url'))
  raise 'Linked paths or queries must not be sent' unless target.path.empty? && target.query.nil?
  calls[target.host] += 1
  raise 'fixture failure' if target.host == 'broken.example'
  case target.host
  when 'invalid.example' then '<html>Not an icon</html>'
  when 'jpeg.example' then jpeg
  when 'wrapped.example' then transparent
  else png
  end
end

begin
  Dir.mktmpdir('link-icons-test-') do |tmp|
    source, dest = File.join(tmp, 'source'), File.join(tmp, 'site')
    social = File.join(source, 'assets/icons/social/x.svg')
    FileUtils.mkdir_p(File.dirname(social))
    File.binwrite(social, svg)
    globe_source = File.join(source, 'assets/icons/links/globe.svg')
    FileUtils.mkdir_p(File.dirname(globe_source))
    File.binwrite(globe_source, globe)
    favicon = File.join(source, 'assets/img/favicons/favicon-96x96.png')
    FileUtils.mkdir_p(File.dirname(favicon))
    File.binwrite(favicon, transparent)
    cache = File.join(source, '.jekyll-cache/link-icons')
    FileUtils.mkdir_p(cache)
    File.binwrite(File.join(cache, 'trustedsec.com.png'), png)
    FileUtils.mkdir_p(File.join(dest, 'notes'))
    page = File.join(dest, 'notes', 'index.html')
    markup = <<~HTML
      <a id="outside" href="https://outside.example">Outside</a>
      <article class="prose">
        <p><a id="github" href="https://github.com/kawakatz?private=not-sent">GitHub</a>
        <a id="x" href="https://x.com/kawakatz">X</a><a id="twitter" href="https://www.twitter.com/name">Twitter</a></p>
        <p><a id="other" href="https://docs.example/a">Docs</a><a href="https://docs.example/b">Docs again</a>
        <a id="www" href="https://www.thehacker.recipes/">Recipes</a></p>
        <p><a id="jpeg" href="https://jpeg.example">JPEG icon</a></p>
        <p><a id="gitlab-pages" href="https://gitlab-com.gitlab.io/article/">GitLab blog</a>
        <a id="gitlab" href="https://gitlab.com/example/project">GitLab project</a></p>
        <p><a id="dirkjanm" href="https://dirkjanm.io/article/">Dirk-jan</a>
        <a id="dirkjanm-www" href="https://www.dirkjanm.io/another/">Dirk-jan www</a></p>
        <p><a id="trusted" href="https://trustedsec.com/blog/example">TrustedSec</a></p>
        <p><a id="synacktiv" href="https://synacktiv.com/publications/example">Synacktiv</a>
        <a id="synacktiv-www" href="https://www.synacktiv.com/publications/example">Synacktiv www</a></p>
        <p><a id="certified" href="https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf">Certified Pre-Owned</a>
        <a id="specterops" href="https://specterops.io/other">SpecterOps</a>
        <a id="specterops-www" href="https://www.specterops.io/other">SpecterOps www</a>
        <a id="specterops-post" href="https://posts.specterops.io/example">SpecterOps post</a></p>
        <p><a id="broken" href="https://broken.example/a">Broken</a><a href="https://broken.example/b">Also broken</a>
        <a id="invalid" href="https://invalid.example">Invalid</a></p>
        <p><a id="internal" href="https://kawakatz.io/about/">About</a><a id="self" href="https://site.example/notes/">Self</a>
        <a id="local" href="http://localhost:4173/">Local</a><a id="relative" href="/about/">Relative</a><a id="email" href="mailto:hello@example.com">Email</a></p>
        <p><a id="internal-www" href="https://www.kawakatz.io/assets/example.pdf#page=2">PDF page</a>
        <a id="protocol-relative" href="//kawakatz.io/about/">Protocol relative</a>
        <a id="external-protocol-relative" href="//github.com/kawakatz">GitHub relative scheme</a>
        <a id="path-relative" href="../assets/example.pdf">Relative PDF</a>
        <a id="section" href="#section">Section</a><a id="blank" href="">Current page</a>
        <a id="query-section" href="?mode=reader#section">Reader section</a></p>
        <p><a id="image" href="https://image.example"><img src="photo.png" alt="Photo"></a>
        <a id="svg" href="https://svg.example"><svg></svg>SVG</a></p>
        <p class="social-links"><a id="social" href="https://social.example">Social</a></p>
        <pre><a id="code" href="https://code.example">Code</a></pre>
        <p><a id="empty" href="https://empty.example"></a></p>
        <p class="work-entry"><a id="wrapped" href="https://wrapped.example"><span class="work-link-label"><em>Wrapped</em></span></a></p>
        <p class="work-entry"><a id="pdf" href="/assets/example.pdf"><span class="work-link-label">Slides ↗</span></a></p>
      </article>
    HTML
    original_links = Nokogiri::HTML(markup).css('a').map { |a| [a['href'], a.text] }
    site = Struct.new(:source, :dest, :config).new(source, dest, { 'url' => 'https://site.example', 'host' => 'localhost', 'baseurl' => '/nested' })
    File.write(page, markup)
    LinkIcons.build(site)
    html = Nokogiri::HTML(File.read(page))
    raise 'Links or labels changed' unless html.css('a').map { |a| [a['href'], a.text] } == original_links
    raise 'GitHub icon missing' unless html.at_css('#github img')['src'] == '/nested/assets/icons/links/github.com.png'
    raise 'Protocol-relative external link routed locally' unless html.at_css('#external-protocol-relative img')['src'] == html.at_css('#github img')['src']
    %w[internal self local relative internal-www protocol-relative path-relative pdf].each do |id|
      raise "Internal URL must use the local site favicon: #{id}" unless html.at_css("##{id} img")['src'] == '/nested/assets/icons/links/favicon-96x96.png'
    end
    raise 'Relative URLs must use the configured site host' unless html.at_css('#pdf img')['data-icon-host'] == 'site.example'
    raise 'Local favicon source changed' unless File.binread(favicon) == transparent
    raise 'Local site icon should not be fetched' if %w[kawakatz.io www.kawakatz.io site.example localhost].any? { |host| calls.key?(host) }
    %w[gitlab-pages gitlab].each do |id|
      raise 'GitLab blog and project must share the GitLab icon' unless html.at_css("##{id} img")['src'] == '/nested/assets/icons/links/gitlab.com.png'
    end
    raise 'GitLab icon must be fetched once from gitlab.com' unless calls['gitlab.com'] == 1 && !calls.key?('gitlab-com.gitlab.io')
    %w[dirkjanm dirkjanm-www].each do |id|
      icon = html.at_css("##{id} img")
      raise 'Dirk-jan must use the local globe at its declared bounds' unless icon['src'] == '/nested/assets/icons/links/globe.svg' && icon['width'] == '20' && icon['height'] == '20'
    end
    published_globe = Nokogiri::XML(File.read(File.join(dest, 'assets/icons/links/globe.svg')))
    raise 'Globe artwork changed' unless published_globe.to_xml == Nokogiri::XML(globe).to_xml
    raise 'Local globe should not request a favicon' if calls.key?('dirkjanm.io') || calls.key?('www.dirkjanm.io')
    raise 'TrustedSec reused the old provider asset' unless html.at_css('#trusted img')['src'] == '/nested/assets/icons/links/trustedsec.com-favicon.png' && File.binread(File.join(cache, 'trustedsec.com-favicon.png')) == transparent
    %w[synacktiv synacktiv-www].each do |id|
      icon = html.at_css("##{id} img")
      raise 'Synacktiv background must retain its original bounds' unless icon['width'] == '32' && icon['height'] == '24'
      image = File.join(dest, icon['src'].delete_prefix('/nested/'))
      source_signature, = Open3.capture3(converter, 'png:-', '-format', '%[signature]', 'info:', stdin_data: png, binmode: true)
      output_signature, = Open3.capture3(converter, image, '-format', '%[signature]', 'info:')
      raise 'Synacktiv artwork or background changed' unless output_signature == source_signature
    end
    %w[certified specterops specterops-www specterops-post].each do |id|
      raise 'SpecterOps links must share the outlined hexagon icon' unless html.at_css("##{id} img")['src'] == '/nested/assets/icons/links/posts.specterops.io.png'
    end
    %w[x twitter].each do |id|
      raise 'X/Twitter must use cropped SVG' unless html.at_css("##{id} img")['src'] == '/nested/assets/icons/links/x.svg'
    end
    cropped_svg = Nokogiri::XML(File.read(File.join(dest, 'assets/icons/links/x.svg')))
    raise 'X shape or About source changed' unless cropped_svg.at_css('path')['d'] == Nokogiri::XML(svg).at_css('path')['d'] && File.binread(social) == svg
    raise 'X whitespace remains' unless cropped_svg.root['viewBox'] == '0.258 0 23.484 24'
    raise 'www host must be preserved for retrieval' unless calls['www.thehacker.recipes'] == 1 && !calls.key?('thehacker.recipes')
    raise 'Sizing must use normalized host' unless html.at_css('#www img')['data-icon-host'] == 'thehacker.recipes'
    raise 'Others wrapper changed' unless html.at_css('#wrapped > .work-link-label > .link-icon-wrap > img.link-icon') && html.at_css('#wrapped em')
    raise 'Others PDF wrapper changed' unless html.at_css('#pdf > .work-link-label > .link-icon-wrap > img.link-icon')
    %w[outside section blank query-section email image svg social code empty broken invalid].each do |id|
      raise "Excluded or failed link got icon: #{id}" if html.at_css("##{id} img.link-icon")
    end
    html.css('img.link-icon').each do |icon|
      raise 'Icon must be grouped without changing link text' unless icon.parent['class'] == 'link-icon-wrap' && icon.parent.text.empty?
      raise 'Icon must be local and decorative' unless icon['src'].start_with?('/nested/assets/icons/') && icon['alt'] == '' && icon['width'].to_i.positive? && icon['height'].to_i.positive?
      raise 'Loading attributes missing' unless icon['loading'] == 'lazy' && icon['decoding'] == 'async'
    end
    raise 'Hosts not deduplicated' unless calls.size == 12 && calls.values.all? { |count| count == 1 }
    raise 'JPEG cache must stay original; publish as lossless PNG' unless html.at_css('#jpeg img')['src'].end_with?('/jpeg.example.png') && File.binread(File.join(source, '.jekyll-cache/link-icons/jpeg.example.jpg')) == jpeg
    %w[github other www wrapped trusted].each do |id|
      icon = html.at_css("##{id} img")
      raise 'Cropped dimensions must reserve the actual aspect ratio' unless icon['width'] == '20' && icon['height'] == '14'
      image = File.join(dest, icon['src'].delete_prefix('/nested/'))
      pixels, error, status = Open3.capture3(converter, image, '-format', '%wx%h %[pixel:p{0,0}]', 'info:')
      expected = %w[wrapped trusted].include?(id) ? 'srgb(101,67,33)' : 'srgb(18,52,86)'
      raise "Padding remains or artwork changed: #{pixels} #{error}" unless status.success? && pixels == "20x14 #{expected}"
    end
    files = Dir.glob(File.join(dest, 'assets/icons/links/*.png'))
    raise 'Unexpected published assets' unless files.size == 11
    output = File.join(dest, 'assets/icons/links/docs.example.png')
    cropped_png = File.binread(output)
    File.delete(output)
    File.write(page, markup)
    LinkIcons.build(site)
    raise 'Cached icon was not republished' unless File.binread(output) == cropped_png
    raise 'Successful icons refetched' unless %w[github.com docs.example www.thehacker.recipes wrapped.example jpeg.example trustedsec.com].all? { |host| calls[host] == 1 }
    raise 'Failed icons must retry next build' unless calls['broken.example'] == 2 && calls['invalid.example'] == 2
    second = File.read(page)
    File.delete(output)
    LinkIcons.build(site)
    raise 'Reprocessing decorated output is not idempotent' unless File.read(page) == second && File.file?(output)
    File.write(File.join(source, '.jekyll-cache/link-icons/docs.example.png'), 'corrupt')
    LinkIcons.build(site)
    raise 'Corrupt cache was not repaired' unless calls['docs.example'] == 2 && File.binread(output) == cropped_png
  end
ensure
  LinkIcons.define_singleton_method(:download, original_download)
end
puts 'Verified trimmed local favicons, cache reuse and recovery, failures, exclusions, baseurl, unchanged links, and idempotence'
