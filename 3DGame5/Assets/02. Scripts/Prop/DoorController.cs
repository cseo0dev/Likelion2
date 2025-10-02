using System;
using System.Collections;
using UnityEngine;
using static Constants;

public class DoorController : MonoBehaviour
{
    [SerializeField] private ESceneName sceneName;
    [SerializeField] private GameObject door;
    [SerializeField] private float openDuration;

    private bool _isOpen;

    private void OnTriggerEnter(Collider other)
    {
        // ¹® ¿­±â
        if (other.CompareTag("Player"))
        {
            StartCoroutine(OpenDoor());
        }
    }

    private IEnumerator OpenDoor()
    {
        float duration = openDuration;
        float distance = 3f;
        Vector3 startPosition = door.transform.position;
        Vector3 endPosition = startPosition + Vector3.up * distance;
        float elapsedTime = 0f;

        while (elapsedTime < duration)
        {
            elapsedTime += Time.deltaTime;
            float t = elapsedTime / duration;
            door.transform.position = Vector3.Lerp(startPosition, endPosition, t);
            yield return null;
        }
        door.transform.position = endPosition;

        GameManager.Instance.LoadScene(sceneName);
    }
}