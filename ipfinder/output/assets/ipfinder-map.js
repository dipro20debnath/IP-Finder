/* IP Finder map drawing, shared by the HTML report and the web dashboard.
   Needs Leaflet. Labels are always inserted as text, never as HTML. */
var IPFinderMap = (function () {
  "use strict";
  function text(value) {
    var el = document.createElement("span");
    el.textContent = value;
    return el;
  }
  function area(lat, lon, radiusKm) { // a point, or the box around its circle
    return L.latLng(lat, lon).toBounds(Math.max(radiusKm || 0, 25) * 2000);
  }
  // OpenStreetMap refuses tile requests without a Referer, and a page opened from
  // disk (file://) cannot send one. Served from a local server it sends one, but
  // reports differ on whether OSM accepts a localhost Referer.
  var STREETS = location.protocol === "file:"
    ? "OpenStreetMap streets (online; refused when opened from disk)"
    : "OpenStreetMap streets (online; may be refused)";

  function draw(m, world) {
    var map = L.map(m.id, { worldCopyJump: true, minZoom: 1 });
    map.attributionControl.setPrefix("Leaflet | Natural Earth (public domain)");
    // Leaflet can only draw shapes once the map has a view, so set it first.
    var view = L.latLngBounds([]);
    m.points.forEach(function (p) { view.extend(area(p.lat, p.lon, p.radius_km)); });
    if (m.consensus) { view.extend(area(m.consensus.lat, m.consensus.lon, 0)); }
    if (m.speed_of_light) {
      view.extend(area(m.speed_of_light.lat, m.speed_of_light.lon, m.speed_of_light.max_km));
    }
    if (view.isValid()) {
      map.fitBounds(view, { padding: [30, 30], maxZoom: 5 });  // country scale
    } else {
      map.setView([20, 0], 2);
    }

    L.geoJSON(world.countries, {
      style: { color: "#7b8794", weight: 0.7, fillColor: "#f5f7fa", fillOpacity: 1 },
      onEachFeature: function (f, layer) {
        layer.bindTooltip(text(f.properties.n), { sticky: true });
      }
    }).addTo(map);
    var cities = L.layerGroup(world.cities.map(function (c) {
      return L.circleMarker([c[1], c[2]], { radius: 2, color: "#3e4c59", weight: 1 })
        .bindTooltip(text(c[0]));
    })).addTo(map);
    var streets = L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19, attribution: "&copy; OpenStreetMap contributors"
    });
    var overlays = { "Cities": cities };
    overlays[STREETS] = streets;
    L.control.layers(null, overlays, { collapsed: false }).addTo(map);

    if (m.speed_of_light) {
      var s = m.speed_of_light;
      L.circle([s.lat, s.lon], { radius: s.max_km * 1000, color: "#b42318", weight: 1.5,
        dashArray: "6 4", fill: false }).bindTooltip(text(s.label)).addTo(map);
      L.circleMarker([s.lat, s.lon], { radius: 5, color: "#b42318", fillOpacity: 1 })
        .bindTooltip(text("You (vantage point)")).addTo(map);
    }
    m.points.forEach(function (p) {
      if (p.radius_km) {
        L.circle([p.lat, p.lon], { radius: p.radius_km * 1000, color: p.color, weight: 1,
          dashArray: "4 4", fillOpacity: 0.06 }).addTo(map);
      }
      L.circleMarker([p.lat, p.lon], { radius: 7, color: p.color, fillOpacity: 0.85 })
        .bindPopup(text(p.label)).bindTooltip(text(p.label)).addTo(map);
    });
    if (m.consensus) {
      L.circleMarker([m.consensus.lat, m.consensus.lon], { radius: 10, color: "#111827",
        weight: 3, fill: false }).bindTooltip(text(m.consensus.label)).addTo(map);
    }
    return map;
  }

  // The HTML report carries its data in the page: draw it straight away.
  var worldData = document.getElementById("ipf-world");
  var mapData = document.getElementById("ipf-maps");
  if (worldData && mapData) {
    var world = JSON.parse(worldData.textContent);
    JSON.parse(mapData.textContent).forEach(function (m) { draw(m, world); });
  }
  return { draw: draw };
})();
