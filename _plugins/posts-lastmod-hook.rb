require "open3"

Jekyll::Hooks.register :posts, :post_init do |post|
  next if post.data["last_modified_at"]
  key = File.basename(post.path, ".md")
  saved = post.site.data.fetch("post_updated", {})[key]
  post.data["last_modified_at"] = saved if saved
  next unless File.directory?(File.join(post.site.source, ".git"))
  date, status = Open3.capture2("git", "log", "-1", "--format=%aI", "--", post.path, chdir: post.site.source)
  post.data["last_modified_at"] = date.strip if status.success? && !date.strip.empty?
end
