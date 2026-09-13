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
    site = Struct.new(:source, :dest, :config).new(source, dest, { 'baseurl' => '/nested' })
    links = { 'pdf' => '/nested/docs/cover.pdf', 'remote' => "#{origin}/start",
      'missing' => "#{origin}/missing", 'broken' => "#{origin}/broken",
      'missing-pdf' => '/nested/docs/missing.pdf', 'broken-pdf' => '/nested/docs/broken.pdf' }
    markup = '<div class="work-entry">' + links.map { |id, href|
      "<a id=\"#{id}\" href=\"#{href}\"><em>#{id}</em> material</a>"
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
    %w[pdf remote].each do |id|
      image = first.at_css("##{id}")['data-preview-image']
      raise "Baseurl or preview image missing: #{id}" unless image&.start_with?('/nested/assets/img/previews/')
      bytes = File.binread(File.join(dest, image.delete_prefix('/nested/')))
      raise "Preview is not WebP: #{id}" unless bytes.start_with?('RIFF') && bytes[8, 4] == 'WEBP'
    end
    %w[missing broken missing-pdf broken-pdf].each do |id|
      raise "Broken preview must fall back to text: #{id}" if first.at_css("##{id}")['data-preview-image']
    end
    raise 'Redirect or relative OG URL not followed' unless %w[/start /article/ /image /cover.jpg].all? { |path| requests[path] == 1 }
    fetched = requests.dup
    second = build.call
    raise 'Cached image changed' unless %w[pdf remote].all? { |id| first.at_css("##{id}")['data-preview-image'] == second.at_css("##{id}")['data-preview-image'] }
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
puts 'Verified PDF rendering, OG redirects, fallbacks, markup, baseurl, cache reuse, failed-download retry, and PDF content invalidation'
