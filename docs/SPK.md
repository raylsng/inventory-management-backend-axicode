# Endpoint SPK API Spec

## 1. Get All SPK
Endpoint: `GET /api/SPK/`

**Response Success :**
 - **200 OK:** Return List of SPK
```json
{

}

```

**Response Error :**


## 2. Get SPK by User ID
Endpoint: `GET /api/SPK/user`

**Response Success :**
 - **200 OK:** Return unique SPK
```json
{

}
```

**Response Error :**


## 3. Request SPK Material
Endpoint: `POST /orders/order

**Resquest Body :**
```json
{
    "materialId": 2,
    "orderQty": 10
}
```

**Response Success :**
 - **200 OK:** Return unique SPK
```json
{
   "id": 8,
   "userId": 1,
   "materialId": 2,
   "orderQty": 10,
   "status": "PENDING",
   "createdAt": "2024-11-13T00:28:08.121Z",
   "updatedAt": "2024-11-13T00:28:08.121Z"
}
```
**Response Error :**




## 4. WH Verify Request SPK
Endpoint: `PATCH /api/SPK/verify/{spk_id}`

** Request Body:**
```json
{
    "status": "ON_PROCESS"
}
```
**Response Success :**
```json
{
    "message": "SPK Request Received Successfully"
}
```

## 5. PH Received Order
Endpoint: `PATCH /orders/received/{orderId}`

**Request Body:**

```json
{
    "status": "DONE"
}
```
**Response Success :**
```json
{
    "message": "SPK Request DONE Successfully"
}
```
**Response Error :**
