async function fetchCapes() {
  try {
    const res = await fetch('/offers');
    if (!res.ok) throw new Error('Failed to fetch capes');
    const data = await res.json();
    return data.offers || [];
  } catch (err) {
    console.error(err);
    return [];
  }
}


async function renderCapes() {
  const capeData = await fetchCapes();
  const officialList = document.getElementById("official-list");
  const communityList = document.getElementById("cape-list");
  officialList.innerHTML = '';
  communityList.innerHTML = '';

  let delay = 0;
  capeData.forEach(cape => {
    const imageSrc = cape.image || 'logo.png';  // fallback image if null
    const card = document.createElement("div");
    card.className = "cape-card";
    card.style.animationDelay = `${delay}s`;
    card.innerHTML = `
      <img src="${imageSrc}" alt="${cape.name}">
      <div class="cape-info">
        <h3>${cape.name}</h3>
        <p>${cape.description}</p>
        <span class="cape-type ${cape.type}">${cape.type.toUpperCase()}</span>
      </div>
    `;
    if (cape.official) officialList.appendChild(card);
    else communityList.appendChild(card);
    delay += 0.15;
  });
}

renderCapes();