"""Move the BE72 August 10 eWeb chart legends into their existing header rows.

Works on downloaded assets only. Deployment must separately back up and verify
the live files. Refuse an unknown asset revision instead of editing by guesswork.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path


JS_SHA256 = "347998e15f0c341f1b30551b746cd9fbf9d22d0987ad642129fdf892f59347cb"
CSS_SHA256 = "713036ea353fb06d392310fca6715a6aee0b5da78d266aaf4b777520973f7328"
MARKER = "labprobe-eweb-header-legend-20261008"


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError(f"Expected exactly one patch anchor: {before[:100]}")
    return text.replace(before, after, 1)


def patch_js(text: str) -> str:
    start = text.index('a("div",{staticClass:"stat-row-spread no-wrap"},[')
    end = text.index(',t._v(" "),a("div",{staticClass:"cumulative-row no-wrap"}', start)
    stats = text[start:end]
    text = replace_once(text, stats,
        'a("div",{staticClass:"traffic-header-row"},[' + stats +
        ',t.renderTrafficHeaderLegend("realtime")])')
    text = replace_once(text, 'staticClass:"bg-subtle-stats"',
        'staticClass:"bg-subtle-stats traffic-stats-header"')

    start = text.index('t.recentWanKeys.length>1?')
    end = text.index(',t._v(" "),a("div",{staticClass:"chart-placeholder w100p"', start)
    filters = text[start:end]
    # The shared row supplies bottom spacing, so the filters need no extra offset.
    filters = replace_once(filters, '"margin-bottom":"8px"', '"margin-bottom":"0"')
    text = text[:start] + 'a("div",{staticClass:"traffic-header-row traffic-recent-header"},[' + filters + \
        ',t.renderTrafficHeaderLegend("recent_wan")])' + text[end:]

    text = replace_once(text, 'trafficChart:null,trafficHistoryDown:[]',
        'trafficChart:null,trafficLegendSelected:{downstream:!0,upstream:!0,connections:!0},trafficHistoryDown:[]')
    text = replace_once(text, 'recentWanChart:null,dailyWanChart:null',
        'recentWanChart:null,recentWanLegendSelected:{downstream:!0,upstream:!0,connections:!0},dailyWanChart:null')

    methods = '''
trafficHeaderLegendSelection:function(tab){
  var state=tab==="recent_wan"?this.recentWanLegendSelected:this.trafficLegendSelected, selected={}, self=this;
  ["downstream","upstream","connections"].forEach(function(key){selected[self.$t("ehr.overview."+key)]=state[key]});
  return selected;
},
toggleTrafficHeaderLegend:function(tab,key){
  var state=tab==="recent_wan"?this.recentWanLegendSelected:this.trafficLegendSelected,
      chart=tab==="recent_wan"?this.recentWanChart:this.trafficChart;
  state[key]=!state[key];
  if(chart)chart.dispatchAction({type:state[key]?"legendSelect":"legendUnSelect",name:this.$t("ehr.overview."+key)});
},
renderTrafficHeaderLegend:function(tab){
  var self=this,h=this.$createElement,state=tab==="recent_wan"?this.recentWanLegendSelected:this.trafficLegendSelected,
      colors=["#0066FF","#42D07D","#F59E0B"];
  return h("div",{staticClass:"traffic-header-legend"},["downstream","upstream","connections"].map(function(key,index){
    return h("button",{key:tab+key,staticClass:"traffic-header-legend-item",class:{"is-off":!state[key]},
      attrs:{type:"button","aria-pressed":String(state[key])},
      on:{click:function(){self.toggleTrafficHeaderLegend(tab,key)}}},[
        h("span",{staticClass:"traffic-header-legend-swatch",style:{color:colors[index]},attrs:{"aria-hidden":"true"}}),
        self._v(self.$t("ehr.overview."+key))]);
  }));
},
'''
    methods = "".join(line.strip() for line in methods.splitlines())
    text = replace_once(text, 'methods:{isWsReady:function', 'methods:{' + methods + 'isWsReady:function')
    text = replace_once(text,
        'legend:{data:[this.$t("ehr.overview.downstream"),this.$t("ehr.overview.upstream"),this.$t("ehr.overview.connections")],',
        'legend:{show:!1,selected:this.trafficHeaderLegendSelection("realtime"),data:[this.$t("ehr.overview.downstream"),this.$t("ehr.overview.upstream"),this.$t("ehr.overview.connections")],')
    text = replace_once(text, 'legend:{data:[t,a,s],',
        'legend:{show:!1,selected:e.trafficHeaderLegendSelection("recent_wan"),data:[t,a,s],')
    return text + "\n/* " + MARKER + " */\n"


def patch_css(text: str) -> str:
    scope = ".ax-index .unifi-main "
    rules = {
        ".traffic-stats-header": "height:auto;min-height:52px;overflow:visible",
        ".traffic-header-row": "display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px 16px;flex-shrink:0",
        ".traffic-header-row>.stat-row-spread": "max-width:100%;min-width:0",
        ".traffic-recent-header": "min-height:22px;margin-bottom:8px",
        ".traffic-header-legend": "display:flex;align-items:center;gap:14px;flex-shrink:0;margin-left:auto",
        ".traffic-header-legend-item": "display:inline-flex;align-items:center;gap:5px;appearance:none;border:0;padding:0;background:transparent;color:#8E95A5;font:inherit;font-size:11px;line-height:22px;white-space:nowrap;cursor:pointer",
        ".traffic-header-legend-item.is-off": "opacity:.45",
        ".traffic-header-legend-item:focus-visible": "outline:2px solid #8E95A5;outline-offset:3px;border-radius:2px",
        ".traffic-header-legend-swatch": "display:inline-block;position:relative;width:19px;height:12px;flex-shrink:0",
        ".traffic-header-legend-swatch:before": 'content:"";position:absolute;left:0;right:0;top:5px;border-top:1px solid currentColor',
        ".traffic-header-legend-swatch:after": 'content:"";position:absolute;left:5px;top:1px;width:8px;height:8px;border:1px solid currentColor;border-radius:50%;background:#fff',
    }
    styles = []
    for selector, body in rules.items():
        # Keep the original component scope, including pseudo-elements.
        if ":" in selector:
            base, pseudo = selector.split(":", 1)
            selector = base + "[data-v-37b90024]:" + pseudo
        else:
            selector += "[data-v-37b90024]"
        styles.append(scope + selector + "{" + body + "}")
    return text + "\n/* " + MARKER + " */\n" + "\n".join(styles) + "\n"


def build_asset(path: Path, expected_sha: str, patch, output_dir: Path) -> dict:
    original = path.read_bytes()
    if hashlib.sha256(original).hexdigest() != expected_sha:
        raise ValueError(f"Unknown original asset revision: {path.name}")
    updated = patch(gzip.decompress(original).decode("utf-8")).encode("utf-8")
    candidate = gzip.compress(updated, compresslevel=9, mtime=0)
    (output_dir / path.name).write_bytes(candidate)
    (output_dir / path.with_suffix("").name).write_bytes(updated)
    return {"name": path.name, "originalSha256": expected_sha,
            "candidateSha256": hashlib.sha256(candidate).hexdigest(), "bytes": len(candidate)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("javascript", type=Path)
    parser.add_argument("stylesheet", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = [
        build_asset(args.javascript, JS_SHA256, patch_js, args.output_dir),
        build_asset(args.stylesheet, CSS_SHA256, patch_css, args.output_dir),
    ]
    (args.output_dir / "candidate-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
