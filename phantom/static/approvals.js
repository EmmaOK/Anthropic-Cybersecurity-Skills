async function decide(approvalId, decision) {
  const btn = event.target;
  btn.disabled = true;
  btn.textContent = decision === 'approved' ? 'Approving…' : 'Denying…';

  try {
    const res = await fetch(`/api/approvals/${approvalId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, decided_by: 'web-ui' }),
    });
    if (!res.ok) throw new Error(await res.text());

    const card = document.getElementById(`card-${approvalId}`);
    if (card) {
      card.style.opacity = '0.4';
      card.style.pointerEvents = 'none';
      const actions = card.querySelector('.card-actions');
      if (actions) {
        actions.innerHTML = `<span class="status-badge status-${decision}">${decision.toUpperCase()}</span>`;
      }
    }

    // Update nav badge
    const badge = document.querySelector('.badge-danger');
    if (badge) {
      const count = parseInt(badge.textContent, 10) - 1;
      if (count <= 0) badge.remove();
      else badge.textContent = count;
    }
  } catch (err) {
    btn.disabled = false;
    btn.textContent = decision === 'approved' ? '✅ Approve' : '❌ Deny';
    alert(`Error: ${err.message}`);
  }
}
