document.querySelectorAll('[data-window-action]').forEach((button) => {
  button.addEventListener('click', () => {
    const action = button.dataset.windowAction;
    window.neutronWindow?.[action]?.();
  });
});
