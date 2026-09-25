require 'fileutils'
require 'net/http'
require 'nokogiri'
require 'open3'
require 'timeout'
require 'uri'

module LinkIcons
  module_function

  MAX_BYTES = 2 * 1024 * 1024

  def build(site)
    cache = File.join(site.source, '.jekyll-cache', 'link-icons')
    FileUtils.mkdir_p(cache)
    baseurl = site.config.fetch('baseurl', '').to_s.chomp('/')
    site_host = normalize_host(URI.parse(site.config['url'].to_s).host || 'kawakatz.io')
    internal_hosts = ['kawakatz.io', site.config['host'], site_host]
      .compact.map { |host| normalize_host(host) }
    icons = {}
    count = 0

    Dir.glob(File.join(site.dest, '**', '*.html')).each do |path|
      document = Nokogiri::HTML(File.binread(path), nil, 'UTF-8')
      previous = document.css('.prose a .link-icon-wrap, .prose a img.link-icon[data-icon-host]')
      changed = !previous.empty?
      previous.remove
      document.css('.prose a[href]').each do |link|
        next if link.text.strip.empty? || link.at_css('img, svg')
        next if link.ancestors.any? { |node| %w[pre code].include?(node.name) || node['class'].to_s.split.include?('social-links') }

        uri = URI.parse(link['href'])
        next unless uri.scheme.nil? || (%w[http https].include?(uri.scheme) && uri.host)
        next if uri.host.nil? && uri.path.to_s.empty?
        source_host = (uri.host || site_host).downcase
        host = normalize_host(source_host)
        internal = internal_hosts.include?(host)
        source_host = site_host if internal
        source_host = 'posts.specterops.io' if host == 'specterops.io'
        source_host = 'gitlab.com' if host == 'gitlab-com.gitlab.io'

        asset = icons.fetch(source_host) do
          input = if internal
                    File.join(site.source, 'assets/img/favicons/favicon-96x96.png')
                  elsif %w[x.com twitter.com].include?(host)
                    File.join(site.source, 'assets/icons/social/x.svg')
                  elsif host == 'dirkjanm.io'
                    File.join(site.source, 'assets/icons/links/globe.svg')
                  else
                    icon_for(source_host, cache)
                  end
          icons[source_host] = input && publish_icon(input, site.dest)
        end
        next unless asset

        image = Nokogiri::XML::Node.new('img', document)
        { 'class' => 'link-icon', 'src' => "#{baseurl}/#{asset[:path]}", 'alt' => '',
          'width' => asset[:width].to_s, 'height' => asset[:height].to_s, 'loading' => 'lazy', 'decoding' => 'async',
          'data-icon-host' => host }.each { |name, value| image[name] = value }
        wrapper = Nokogiri::XML::Node.new('span', document)
        wrapper['class'] = 'link-icon-wrap'
        wrapper.add_child(image)
        target = link.at_css('.work-link-label') || link
        target.children.first.add_previous_sibling(wrapper)
        changed = true
        count += 1
      rescue URI::InvalidURIError
        next
      end
      File.binwrite(path, document.to_html) if changed
    end
    Jekyll.logger.info 'Link icons:', "#{count} links, #{icons.values.compact.size} local icons"
  end

  def normalize_host(host)
    host.downcase.sub(/\Awww\./, '')
  end

  def publish_icon(input, destination)
    svg = File.extname(input) == '.svg'
    relative = "assets/icons/links/#{File.basename(input, '.*')}.#{svg ? 'svg' : 'png'}"
    output = File.join(destination, relative)
    FileUtils.mkdir_p(File.dirname(output))
    if svg
      document = Nokogiri::XML(File.binread(input))
      # Tight bounds of the X path; leave the shared About asset unchanged.
      document.root['viewBox'] = '0.258 0 23.484 24' if input.end_with?('/assets/icons/social/x.svg')
      File.binwrite(output, document.to_xml)
      width, height = document.root['viewBox'].split.last(2).map(&:to_i)
    else
      converter = ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? { |dir| File.executable?(File.join(dir, 'magick')) } ? 'magick' : 'convert'
      # Synacktiv's black square is part of the favicon, not outer padding.
      trim = normalize_host(File.basename(input, '.*')) == 'synacktiv.com' ? [] : ['-trim', '+repage']
      dimensions, error, status = Open3.capture3(converter, '-limit', 'memory', '128MiB', '-limit', 'map', '256MiB',
        "#{input}[0]", *trim, '-strip', '-write', output, '-format', '%w %h', 'info:')
      raise "#{converter}: #{error.lines.first.to_s.strip}" unless status.success?
      width, height = dimensions.split.map(&:to_i)
    end
    { path: relative, width: width, height: height }
  rescue StandardError => error
    Jekyll.logger.warn 'Link icons:', "#{File.basename(input)}: #{error.message}"
    nil
  end

  def image_extension(body)
    return unless body.bytesize.between?(45, MAX_BYTES)
    return 'png' if body.start_with?("\x89PNG\r\n\x1A\n".b) && body[12, 4] == 'IHDR' && body.end_with?("\0\0\0\0IEND\xAE\x42\x60\x82".b)
    'jpg' if body.start_with?("\xFF\xD8\xFF".b) && body.end_with?("\xFF\xD9".b)
  end

  def icon_for(host, cache)
    official = normalize_host(host) == 'trustedsec.com'
    name = official ? "#{host}-favicon" : host
    %w[png jpg].each do |extension|
      path = File.join(cache, "#{name}.#{extension}")
      return path if File.file?(path) && File.size(path) <= MAX_BYTES && image_extension(File.binread(path)) == extension
    end

    query = URI.encode_www_form('domain_url' => "https://#{host}", 'sz' => '64')
    url = official ? 'https://trustedsec.com/favicons/favicon-32x32.png' : "https://www.google.com/s2/favicons?#{query}"
    body = download(url)
    extension = image_extension(body)
    raise 'Unsupported or invalid icon image' unless extension
    path = File.join(cache, "#{name}.#{extension}")
    File.binwrite(path, body)
    path
  rescue StandardError => error
    Jekyll.logger.warn 'Link icons:', "#{host}: #{error.message}"
    nil
  end

  def download(url, redirects = 4)
    uri = URI.parse(url)
    raise 'Only HTTP(S) icon sources are supported' unless %w[http https].include?(uri.scheme)
    Timeout.timeout(15) do
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: 4, read_timeout: 8) do |http|
        http.request(Net::HTTP::Get.new(uri, 'User-Agent' => 'Mozilla/5.0 (compatible; kawakatz.io build)')) do |response|
          if response.is_a?(Net::HTTPRedirection)
            raise 'Too many redirects' if redirects.zero?
            return download(URI.join(url, response.fetch('location')).to_s, redirects - 1)
          end
          raise "HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)
          body = ''.b
          response.read_body do |chunk|
            raise 'Icon source exceeds 2 MB' if body.bytesize + chunk.bytesize > MAX_BYTES
            body << chunk
          end
          return body
        end
      end
    end
  end
end

Jekyll::Hooks.register :site, :post_write, priority: :low do |site|
  LinkIcons.build(site)
end
