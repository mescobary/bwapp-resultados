import json, collections, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJ = {"Core bWAPP":"semgrep/out/core.json","admin":"semgrep/out/admin.json","soap (NuSOAP)":"semgrep/out/soap.json"}
SEV = {"ERROR":"Alta","WARNING":"Media","INFO":"Baja"}
SEVCOL = {"Alta":"#c0392b","Media":"#e67e22","Baja":"#2980b9"}
os.makedirs("charts", exist_ok=True)

data = {}
for name,path in PROJ.items():
    data[name] = json.load(open(path))["results"]

# aggregates
by_proj_sev = collections.defaultdict(lambda: collections.Counter())
by_owasp = collections.Counter()
by_cat = collections.Counter()
by_sev_total = collections.Counter()
by_proj_total = collections.Counter()
files_core = collections.Counter()
for name, results in data.items():
    for r in results:
        md = r["extra"]["metadata"]
        sev = SEV.get(r["extra"]["severity"], r["extra"]["severity"])
        by_proj_sev[name][sev]+=1
        by_sev_total[sev]+=1
        by_proj_total[name]+=1
        by_owasp[md.get("owasp","(sin OWASP)")]+=1
        by_cat[md.get("category", r["check_id"].split(".")[-1])]+=1
        if name=="Core bWAPP":
            files_core[os.path.basename(r["path"])]+=1

total = sum(by_proj_total.values())
# posture score: weighted
W={"Alta":5,"Media":3,"Baja":1}
score = sum(W[s]*c for s,c in by_sev_total.items())

summary = {
 "total": total,
 "by_project": dict(by_proj_total),
 "by_severity": dict(by_sev_total),
 "by_owasp": dict(by_owasp),
 "by_category": dict(by_cat),
 "weighted_score": score,
 "top_files_core": files_core.most_common(10),
 "by_proj_sev": {k:dict(v) for k,v in by_proj_sev.items()},
}
json.dump(summary, open("semgrep/summary.json","w"), ensure_ascii=False, indent=2)

plt.rcParams.update({"font.size":11,"axes.spines.top":False,"axes.spines.right":False,"figure.dpi":130})
SEVORDER=["Alta","Media","Baja"]

# Chart 1: stacked bar findings by project x severity
projs=list(PROJ.keys())
fig,ax=plt.subplots(figsize=(7.2,4))
bottom=[0]*len(projs)
for s in SEVORDER:
    vals=[by_proj_sev[p].get(s,0) for p in projs]
    ax.bar(projs,vals,bottom=bottom,label=s,color=SEVCOL[s])
    bottom=[b+v for b,v in zip(bottom,vals)]
for i,p in enumerate(projs):
    ax.text(i,by_proj_total[p]+1,str(by_proj_total[p]),ha="center",fontweight="bold")
ax.set_ylabel("Hallazgos"); ax.set_title("Hallazgos por proyecto y severidad")
ax.legend(title="Severidad"); plt.tight_layout(); plt.savefig("charts/01_proyecto_severidad.png"); plt.close()

# Chart 2: OWASP categories (horizontal)
items=by_owasp.most_common()
labels=[k.split(" - ")[0]+" "+k.split(" - ")[1] if " - " in k else k for k,_ in items]
vals=[v for _,v in items]
fig,ax=plt.subplots(figsize=(8,4.3))
ax.barh(labels[::-1],vals[::-1],color="#34495e")
for i,v in enumerate(vals[::-1]): ax.text(v+0.5,i,str(v),va="center",fontweight="bold")
ax.set_xlabel("Hallazgos"); ax.set_title("Hallazgos por categoría OWASP Top 10 (2021)")
plt.tight_layout(); plt.savefig("charts/02_owasp.png"); plt.close()

# Chart 3: by vulnerability type
items=by_cat.most_common()
fig,ax=plt.subplots(figsize=(8,4.3))
ax.barh([k for k,_ in items][::-1],[v for _,v in items][::-1],color="#16a085")
for i,(k,v) in enumerate(items[::-1]): ax.text(v+0.5,i,str(v),va="center",fontweight="bold")
ax.set_xlabel("Hallazgos"); ax.set_title("Hallazgos por tipo de vulnerabilidad")
plt.tight_layout(); plt.savefig("charts/03_tipo.png"); plt.close()

# Chart 4: donut severity
fig,ax=plt.subplots(figsize=(5.2,4.2))
svals=[by_sev_total.get(s,0) for s in SEVORDER]
ax.pie(svals,labels=[f"{s}\n{v}" for s,v in zip(SEVORDER,svals)],colors=[SEVCOL[s] for s in SEVORDER],
       autopct="%1.0f%%",pctdistance=0.8,wedgeprops=dict(width=0.42,edgecolor="w"))
ax.set_title("Distribución por severidad (total)")
plt.tight_layout(); plt.savefig("charts/04_severidad_donut.png"); plt.close()

# Chart 5: top files core
tf=files_core.most_common(10)
fig,ax=plt.subplots(figsize=(8,4.3))
ax.barh([k for k,_ in tf][::-1],[v for _,v in tf][::-1],color="#8e44ad")
for i,(k,v) in enumerate(tf[::-1]): ax.text(v+0.1,i,str(v),va="center",fontweight="bold")
ax.set_xlabel("Hallazgos"); ax.set_title("Top 10 archivos con más hallazgos (Core bWAPP)")
plt.tight_layout(); plt.savefig("charts/05_top_archivos.png"); plt.close()

print("OK charts + summary")
print(json.dumps(summary, ensure_ascii=False, indent=1))
