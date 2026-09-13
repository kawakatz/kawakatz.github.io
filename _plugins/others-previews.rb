require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'nokogiri'
require 'open3'
require 'pathname'
require 'tmpdir'
require 'timeout'

module OthersPreviews
  module_function

  def download(url, redirects = 4)
    uri = URI(url)
    raise 'Only HTTP(S) preview sources are supported' unless %w[http https].include?(uri.scheme)
    Timeout.timeout(20) do
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: 5, read_timeout: 8) do |http|
        http.request(Net::HTTP::Get.new(uri, 'User-Agent' => 'Mozilla/5.0 (compatible; kawakatz.io preview builder)')) do |response|
          if response.is_a?(Net::HTTPRedirection)
            raise 'Too many redirects' if redirects.zero?
            return download(URI.join(url, response.fetch('location')).to_s, redirects - 1)
          end
          raise "HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)
          body = ''.b
          response.read_body do |chunk|
            raise 'Preview source exceeds 20 MB' if body.bytesize + chunk.bytesize > 20 * 1024 * 1024
            body << chunk
          end
          return [body, uri.to_s, response['content-type'].to_s]
        end
      end
    end
  end

  def thumbnail(data, pdf, cache)
    name = "#{Digest::SHA256.hexdigest(data)[0, 20]}.webp"
    output = File.join(cache, name)
    return name if File.file?(output)
    Dir.mktmpdir('others-preview-') do |tmp|
      input = File.join(tmp, pdf ? 'source.pdf' : 'source')
      File.binwrite(input, data)
      if pdf
        run('pdftoppm', '-f', '1', '-singlefile', '-scale-to', '800', '-png', input, File.join(tmp, 'cover'))
        input = File.join(tmp, 'cover.png')
      end
      converter = ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, 'magick')) } ? 'magick' : 'convert'
      result = File.join(tmp, 'preview.webp')
      run(converter, '-limit', 'memory', '128MiB', '-limit', 'map', '256MiB', "#{input}[0]", '-auto-orient', '-thumbnail', '800x450>', '-strip', '-quality', '82', result)
      FileUtils.mv(result, output)
    end
    name
  end

  def run(*command)
    _out, error, status = Open3.capture3(*command)
    raise "#{command.first}: #{error.lines.first.to_s.strip}" unless status.success?
  end

  def preview(href, source, baseurl, cache, previous)
    uri = URI(href)
    if uri.host.nil?
      path = Pathname.new(File.join(source, URI::DEFAULT_PARSER.unescape(uri.path.delete_prefix(baseurl)).delete_prefix('/'))).realpath
      raise 'Local previews must be PDFs inside the site source' unless path.to_s.start_with?(File.realpath(source) + '/') && path.extname.downcase == '.pdf'
      return { 'label' => 'PDF', 'image' => thumbnail(path.binread, true, cache) }
    end
    if previous && Time.now.to_i - previous.fetch('checked_at', 0) < 86_400 && (!previous['image'] || File.file?(File.join(cache, previous['image'])))
      return previous
    end
    result = { 'label' => uri.host.delete_prefix('www.'), 'checked_at' => Time.now.to_i }
    data, url, type = download(href)
    if type.include?('application/pdf') || data.start_with?('%PDF-')
      return result.merge('label' => 'PDF', 'image' => thumbnail(data, true, cache))
    end
    html = Nokogiri::HTML(data)
    result['label'] = html.at_css('meta[property="og:site_name"]')&.[]('content') || result['label']
    image = html.at_css('meta[property="og:image"], meta[property="og:image:url"]')&.[]('content') || html.at_css('meta[name="twitter:image"], meta[property="twitter:image"]')&.[]('content')
    if image && !image.strip.empty?
      data, = download(URI.join(url, image.strip).to_s)
      result['image'] = thumbnail(data, false, cache)
    end
    result
  rescue StandardError => error
    Jekyll.logger.warn 'Others preview:', "#{href}: #{error.message}"
    previous || { 'label' => uri&.host || 'PDF' }
  end

  def build(site)
    page = File.join(site.dest, 'others', 'index.html')
    return unless File.file?(page)
    cache = File.join(site.source, '.jekyll-cache', 'others-previews')
    FileUtils.mkdir_p(cache)
    index = File.join(cache, 'index.json')
    saved = File.file?(index) ? JSON.parse(File.read(index)) : {}
    current = {}
    html = Nokogiri::HTML(File.read(page))
    baseurl = site.config.fetch('baseurl', '').to_s
    html.css('.work-entry a[href]').each do |link|
      unless link.at_css('.work-link-label')
        label = Nokogiri::XML::Node.new('span', html)
        label['class'] = 'work-link-label'
        label.add_child(link.children)
        link.add_child(label)
      end
      href = link['href']
      next unless href.start_with?('/', 'https://', 'http://')
      entry = current[href] ||= preview(href, site.source, baseurl, cache, saved[href])
      link['data-preview'] = entry.fetch('label')
      link.remove_attribute('data-preview-image')
      next unless entry['image'] && File.file?(File.join(cache, entry['image']))
      output = File.join('assets', 'img', 'previews', entry['image'])
      FileUtils.mkdir_p(File.dirname(File.join(site.dest, output)))
      FileUtils.cp(File.join(cache, entry['image']), File.join(site.dest, output))
      link['data-preview-image'] = "#{baseurl}/#{output}"
    end
    File.write(index, JSON.pretty_generate(current))
    File.write(page, html.to_html)
    Jekyll.logger.info 'Others previews:', "#{current.values.count { |entry| entry['image'] }} / #{current.size} links with images"
  end
end

Jekyll::Hooks.register :site, :post_write do |site|
  OthersPreviews.build(site)
end
