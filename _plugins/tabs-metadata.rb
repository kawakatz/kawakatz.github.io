# Static pages have no publication date; collection documents otherwise use build time.
Jekyll::Hooks.register :tabs, :pre_render do |_tab, payload|
  payload["page"] = payload["page"].to_h.merge("date" => nil)
end
