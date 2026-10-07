from backend.misp_galaxy import enricher; enricher.initialize(); 
for k,v in enricher.alias_map.items():
    if v == 'Pay2Key': print(k, '->', v)
