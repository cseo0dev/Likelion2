using System.Collections.Generic;
using UnityEngine;
using static Constants;

public class MeleeController : MonoBehaviour, IWeaponObservable<GameObject>
{
    [SerializeField] private WeaponTriggerZone[] triggerZones; // 구의 좌표와 반지름 정보
    [SerializeField] private LayerMask targetLayerMask;

    private HashSet<Collider> _hitColliders;
    private Vector3[] _previousTriggerPositions;

    private List<IWeaponObserver<GameObject>> _observers =
        new List<IWeaponObserver<GameObject>>();

    private bool _isTriggering;

    private void Awake()
    {
        _previousTriggerPositions = new Vector3[triggerZones.Length];
        _hitColliders = new HashSet<Collider>(); // 충돌이 발생했을 때 충돌 대상을 담을 공간

        _isTriggering = false;
    }

    public void StartTrigger()
    {
        _hitColliders.Clear();
        for (int i = 0; i < triggerZones.Length; i++)
        {
            _previousTriggerPositions[i] = GetTriggerWorldPosition(triggerZones[i].position);
        }

        _isTriggering = true;
    }

    public void EndTrigger()
    {
        foreach (var hitCollider in _hitColliders)
        {
            Notify(hitCollider.gameObject);
        }

        _isTriggering = false;
    }

    // 충돌 감지
    private void FixedUpdate()
    {
        if (!_isTriggering) return;

        for (int i = 0; i < triggerZones.Length; i++)
        {
            var worldPosition = GetTriggerWorldPosition(triggerZones[i].position);
            var direction = worldPosition - _previousTriggerPositions[i];
            Ray ray = new Ray(worldPosition, direction);
            RaycastHit[] hits = new RaycastHit[10];

            var hitCount = Physics.SphereCastNonAlloc(ray, triggerZones[i].radius, hits,
                direction.magnitude, targetLayerMask);

            for (int j = 0; j < hitCount; j++)
            {
                var hit = hits[j];
                if (!_hitColliders.Contains(hit.collider))
                {
                    _hitColliders.Add(hit.collider);
                }
            }
            _previousTriggerPositions[i] = worldPosition;
        }
    }

    private Vector3 GetTriggerWorldPosition(Vector3 position)
    {
        return transform.position + transform.TransformDirection(position);
    }

    private void OnDrawGizmos()
    {
        if (!Application.isPlaying) return;

        for (int i = 0; i < triggerZones.Length; i++)
        {
            var worldPosition = GetTriggerWorldPosition(triggerZones[i].position);
            var direction = worldPosition - _previousTriggerPositions[i];
            Gizmos.color = Color.green;
            Gizmos.DrawWireSphere(worldPosition, triggerZones[i].radius);
            Gizmos.color = Color.red;
            Gizmos.DrawWireSphere(worldPosition + direction, triggerZones[i].radius);
        }
    }

    public void Subscribe(IWeaponObserver<GameObject> observer)
    {
        if (!_observers.Contains(observer))
        {
            _observers.Add(observer);
        }
    }

    public void Unsubscribe(IWeaponObserver<GameObject> observer)
    {
        _observers.Remove(observer);
    }

    public void Notify(GameObject value)
    {
        foreach (var observer in _observers)
        {
            observer.OnNext(value);
        }
    }
}
