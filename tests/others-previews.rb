require 'jekyll'
require 'webrick'
require_relative '../_plugins/others-previews'

root = File.expand_path('..', __dir__)
requests = Hash.new(0)
fail_article = false
ready = Queue.new
server = WEBrick::HTTPServer.new(BindAddress: '127.0.0.1', Port: 0, AccessLog: [],
  Logger: WEBrick::Log.new(File::NULL), StartCallback: -> { ready << true })
server.mount_proc('/') do |request, response|
  requests[request.path] += 1
  response['Content-Type'] = 'text/html'
  case request.path
  when '/start', '/image'
    response.status = 302
    response['Location'] = request.path == '/start' ? '/article/' : '/cover.jpg'
  when '/article/'
    response.status = 503 if fail_article
    response.body = '<meta content="Fixture Site" property="og:site_name"><meta content="../image" property="og:image">'
  when '/cover.jpg'
    response['Content-Type'] = 'image/jpeg'
    response.body = File.binread(File.join(root, 'assets/img/avatar/kawakatz.jpg'))
  when '/missing'
    response.body = '<title>No image metadata</title>'
  when '/broken'
    response.body = '<meta content="/bad-image" property="og:image">'
  else
    response.status = 404
    response.body = 'Missing preview'
  end
end
thread = Thread.new { server.start }
ready.pop
origin = "http://127.0.0.1:#{server.config[:Port]}"

begin
  Dir.mktmpdir('others-previews-test-') do |tmp|
    source, dest = File.join(tmp, 'source'), File.join(tmp, 'site')
    FileUtils.mkdir_p([File.join(source, 'docs'), File.join(dest, 'others')])
    pdf = File.join(source, 'docs', 'cover.pdf')
    FileUtils.cp(File.join(root, 'assets/pdf/20250816/edr_bypass_basics.pdf'), pdf)
    File.write(File.join(source, 'docs', 'broken.pdf'), 'Not a PDF')
    FileUtils.cp(File.join(root, 'assets/img/avatar/kawakatz.jpg'), File.join(source, 'docs', 'cover.jpg'))
    site = Struct.new(:source, :dest, :config).new(source, dest, { 'baseurl' => '/nested' })
    links = { 'pdf' => '/nested/docs/cover.pdf', 'remote' => "#{origin}/start",
      'missing' => "#{origin}/missing", 'broken' => "#{origin}/broken",
      'missing-pdf' => '/nested/docs/missing.pdf', 'broken-pdf' => '/nested/docs/broken.pdf',
      'cover' => "#{origin}/book", 'missing-cover' => "#{origin}/book-missing" }
    # Pages without usable metadata, such as Amazon books, can name a local picture instead.
    covers = { 'cover' => '/nested/docs/cover.jpg', 'missing-cover' => '/nested/docs/missing.jpg' }
    markup = '<div class="work-entry">' + links.map { |id, href|
      cover = covers[id] ? " data-preview-source=\"#{covers[id]}\"" : ''
      "<a id=\"#{id}\" href=\"#{href}\"#{cover}><em>#{id}</em> material</a>"
    }.join + '</div><a id="outside" href="/nested/docs/cover.pdf">Outside</a>'
    page = File.join(dest, 'others', 'index.html')
    build = lambda do
      File.write(page, markup)
      OthersPreviews.build(site)
      Nokogiri::HTML(File.read(page))
    end
    first = build.call
    links.each do |id, href|
      link = first.at_css("##{id}")
      raise "Link or label changed: #{id}" unless link['href'] == href && link.text == "#{id} material"
      raise "Missing wrapper: #{id}" unless link.css('> .work-link-label > em').size == 1
      raise "Missing text preview: #{id}" if link['data-preview'].to_s.empty?
    end
    raise 'Unrelated link modified' if first.at_css('#outside')['data-preview'] || first.at_css('#outside .work-link-label')
    raise 'PDF label missing' unless first.at_css('#pdf')['data-preview'] == 'PDF'
    raise 'OG site name missing' unless first.at_css('#remote')['data-preview'] == 'Fixture Site'
    raise 'Local cover must keep the link host as its label' unless %w[cover missing-cover].all? { |id| first.at_css("##{id}")['data-preview'] == '127.0.0.1' }
    raise 'Local cover pages must not be fetched' unless requests['/book'].zero? && requests['/book-missing'].zero?
    raise 'Cover source attribute must not be published' unless first.css('[data-preview-source]').empty?
    %w[pdf remote cover].each do |id|
      image = first.at_css("##{id}")['data-preview-image']
      raise "Baseurl or preview image missing: #{id}" unless image&.start_with?('/nested/assets/img/previews/')
      bytes = File.binread(File.join(dest, image.delete_prefix('/nested/')))
      raise "Preview is not WebP: #{id}" unless bytes.start_with?('RIFF') && bytes[8, 4] == 'WEBP'
    end
    cover = File.join(dest, first.at_css('#cover')['data-preview-image'].delete_prefix('/nested/'))
    converter = ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, 'magick')) } ? %w[magick identify] : %w[identify]
    size, = Open3.capture3(*converter, '-format', '%wx%h', cover)
    raise "Local cover must fill the 16:9 card: #{size}" unless size == '800x450'
    %w[missing broken missing-pdf broken-pdf missing-cover].each do |id|
      raise "Broken preview must fall back to text: #{id}" if first.at_css("##{id}")['data-preview-image']
    end
    raise 'Redirect or relative OG URL not followed' unless %w[/start /article/ /image /cover.jpg].all? { |path| requests[path] == 1 }
    fetched = requests.dup
    second = build.call
    raise 'Cached image changed' unless %w[pdf remote cover].all? { |id| first.at_css("##{id}")['data-preview-image'] == second.at_css("##{id}")['data-preview-image'] }
    failed = %w[/broken /bad-image]
    raise 'Successful previews or missing metadata were refetched' unless (fetched.keys - failed).all? { |path| requests[path] == fetched[path] }
    raise 'Failed preview was not retried' unless failed.all? { |path| requests[path] == fetched[path] + 1 }
    File.open(pdf, 'ab') { |file| file.write("\n% Preview content hash check\n") }
    third = build.call
    expected = Digest::SHA256.file(pdf).hexdigest[0, 20] + '.webp'
    raise 'PDF content change reused stale preview' unless third.at_css('#pdf')['data-preview-image'].end_with?(expected) && third.at_css('#pdf')['data-preview-image'] != first.at_css('#pdf')['data-preview-image']
    index = File.join(source, '.jekyll-cache', 'others-previews', 'index.json')
    saved = JSON.parse(File.read(index))
    saved.fetch(links['remote'])['checked_at'] = 0
    File.write(index, JSON.generate(saved))
    fail_article = true
    cached_image = first.at_css('#remote')['data-preview-image']
    published_image = File.join(dest, cached_image.delete_prefix('/nested/'))
    File.delete(published_image)
    fallback = build.call.at_css('#remote')['data-preview-image']
    timestamp = JSON.parse(File.read(index)).fetch(links['remote'])['checked_at']
    raise 'Failed refresh must republish the cached image and remain due for retry' unless fallback == cached_image && File.file?(published_image) && timestamp == 0 && requests['/article/'] == fetched['/article/'] + 1
  end
ensure
  server.shutdown
  thread.join
end
puts 'Verified PDF rendering, OG redirects, local covers, fallbacks, markup, baseurl, cache reuse, failed-download retry, and PDF content invalidation'
