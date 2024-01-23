document.getElementById('submit-btn').addEventListener('click', e => {
  e.preventDefault();
  const formData = new FormData(document.querySelector('form'));
  const data = {};
  for (const entry of formData.entries()) {
    data[entry[0]] = entry[1];
  }

  fetch('/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
    .then(response => {
      if (response.redirected) {
        window.location.href = response.url;
      }
    })
    .catch(err => {
      console.error(err);
    });
});
